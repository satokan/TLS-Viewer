import logging
import concurrent.futures
from typing import List
from scanner.loader import DomainLoader, DomainEntry
from scanner.scanner import TLSScanner
from scanner.geoip import GeoIPResolver
from scanner.database import get_db
from scanner.models import Domain, ScanResult
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

def process_domain(domain_entry: DomainEntry) -> ScanResult:
    """
    Worker function to process a single domain.
    This runs in a separate process.
    """
    scanner = TLSScanner()
    
    # 1. Scan standard TLS/SSL
    result = scanner.scan_domain(domain_entry.domain)
    
    # 2. Scan for PQC support (if successful)
    if result.scan_status == "SUCCESS":
        try:
            pqc_info = scanner.scan_domain_pqc(domain_entry.domain)
            result.pqc_info = pqc_info
        except Exception as e:
            logger.error(f"PQC scan failed for {domain_entry.domain}: {e}")
            
        # 3. GeoIP Resolution
        try:
            geoip = GeoIPResolver()
            geo_location = geoip.resolve(domain_entry.domain)
            if geo_location:
                result.geo_location = geo_location
            geoip.close()
        except Exception as e:
            logger.error(f"GeoIP resolution failed for {domain_entry.domain}: {e}")
        
    return result

class ScanManager:
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.loader = DomainLoader()

    def run_scan(self, csv_path: str, limit: int = 100):
        logger.info(f"Loading domains from {csv_path} (limit={limit})")
        domains = self.loader.load_from_csv(csv_path, limit=limit)
        
        logger.info(f"Starting scan for {len(domains)} domains with {self.max_workers} workers")
        
        results = []
        with concurrent.futures.ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            # Map domains to futures
            future_to_domain = {executor.submit(process_domain, d): d for d in domains}
            
            for future in concurrent.futures.as_completed(future_to_domain):
                domain_entry = future_to_domain[future]
                try:
                    result = future.result()
                    results.append((domain_entry, result))
                    logger.info(f"Completed {domain_entry.domain}: {result.scan_status}")
                except Exception as exc:
                    logger.error(f"{domain_entry.domain} generated an exception: {exc}")
                    # Create an error result for the failed domain
                    error_result = ScanResult(
                        scan_date=datetime.now(timezone.utc),
                        scan_status="ERROR",
                        error_message=str(exc)
                    )
                    results.append((domain_entry, error_result))
        
        self._save_results(results)

    def _save_results(self, results: List[tuple[DomainEntry, ScanResult]]):
        logger.info("Saving results to database...")
        db = next(get_db())
        try:
            for domain_entry, scan_result in results:
                # 1. Get or Create Domain
                domain = db.query(Domain).filter_by(name=domain_entry.domain).first()
                if not domain:
                    domain = Domain(
                        name=domain_entry.domain,
                        tld=domain_entry.tld,
                        global_rank=domain_entry.rank
                    )
                    db.add(domain)
                    db.flush() # Get ID
                
                # 2. Save Scan Result
                scan_result.domain_id = domain.id
                db.add(scan_result)
            
            db.commit()
            logger.info("Results saved successfully.")
        except Exception as e:
            logger.error(f"Error saving results: {e}")
            db.rollback()
        finally:
            db.close()
