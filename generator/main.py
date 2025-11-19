import os
import logging
from datetime import datetime
from collections import Counter
from sqlalchemy.orm import Session
from jinja2 import Environment, FileSystemLoader

from scanner.database import get_db
from scanner.models import ScanResult, TLSVersion, CipherSuite, Certificate, PQCInfo

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_dashboard(output_dir: str = "output"):
    """Generate the static dashboard."""
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Copy static assets
    static_dir = os.path.join(output_dir, "static")
    os.makedirs(static_dir, exist_ok=True)
    os.system(f"cp generator/static/* {static_dir}/")
    
    # Connect to DB
    db: Session = next(get_db())
    
    try:
        # Fetch all successful scans
        scans = db.query(ScanResult).filter(ScanResult.scan_status == "SUCCESS").all()
        total_scans = len(scans)
        
        if total_scans == 0:
            logger.warning("No successful scans found. Dashboard will be empty.")
            return

        # Aggregation variables
        pqc_count = 0
        total_score = 0
        commercial_ca_count = 0
        
        grade_dist = Counter()
        tls_dist = Counter()
        pqc_algo_dist = Counter()
        ca_dist = Counter()
        cipher_dist = Counter()
        geo_dist = Counter()
        
        all_scans_data = []
        
        for scan in scans:
            # PQC Stats
            is_pqc = False
            if scan.pqc_info and scan.pqc_info.is_supported:
                pqc_count += 1
                is_pqc = True
                # Count algorithms
                if scan.pqc_info.supported_suites:
                    for suite in scan.pqc_info.supported_suites.split(','):
                        if suite.strip():
                            pqc_algo_dist[suite.strip()] += 1
            
            # Score & Grade
            if scan.scan_status == "ERROR":
                grade = "Error"
                score = 0.0
            else:
                grade = scan.grade or "Unknown"
                score = float(scan.score) if scan.score is not None else 0.0
            
            total_score += score
            grade_dist[grade] += 1
            
            # CA Stats
            ca_type = "Unknown"
            issuer_name = "Unknown"
            if scan.certificate:
                ca_type = scan.certificate.ca_type or "Unknown"
                if ca_type == "COMMERCIAL_CA":
                    commercial_ca_count += 1
                
                # Parse Issuer DN to get friendly name (O or CN)
                # Format is usually <Name(CN=..., O=..., C=...)> or similar string representation
                import re
                issuer_str = scan.certificate.issuer
                if issuer_str:
                    # Try to find O=...
                    # Handle potential escaped commas like "Cloudflare\, Inc."
                    # We capture until we hit a comma that is NOT preceded by a backslash, or end of string
                    # But simpler regex: just take until next comma, then clean up
                    
                    # Better approach: use a regex that handles optional quotes
                    # Pattern: O=(?:")?([^",]+(?:\\.[^",]+)*)(?:")?
                    # But let's stick to simple cleaning for now as the string format varies
                    
                    target = None
                    o_match = re.search(r"O=([^,]+)", issuer_str)
                    if o_match:
                        target = o_match.group(1)
                    else:
                        cn_match = re.search(r"CN=([^,]+)", issuer_str)
                        if cn_match:
                            target = cn_match.group(1)
                    
                    if target:
                        # Clean up: remove quotes, unescape backslashes
                        issuer_name = target.strip().strip('"').strip("'").replace("\\", "").strip()
                    else:
                        issuer_name = issuer_str[:30] + "..." if len(issuer_str) > 30 else issuer_str
            
            # Use Issuer Name for distribution instead of generic type
            ca_dist[issuer_name] += 1
            
            # TLS Stats
            max_tls = "Unknown"
            if scan.tls_versions:
                supported = [v.version for v in scan.tls_versions if v.is_supported]
                if supported:
                    # Simple sort (works because TLS 1.3 > TLS 1.2 lexicographically)
                    max_tls = sorted(supported)[-1]
            tls_dist[max_tls] += 1
            
            # Cipher Suite Stats
            if scan.cipher_suites:
                for suite in scan.cipher_suites:
                    cipher_dist[suite.name] += 1
            
            # GeoIP Stats
            country = "Unknown"
            if scan.geo_location and scan.geo_location.country_name:
                country = scan.geo_location.country_name
            geo_dist[country] += 1
            
            # Full Scan Data (for client-side filtering & details)
            all_scans_data.append({
                "domain": scan.domain.name,
                "grade": grade,
                "score": round(score, 1),
                "pqc_supported": is_pqc,
                "tls_version": max_tls,
                "ca_type": ca_type,
                "issuer": issuer_name,  # Add issuer name
                "country": country,
                "date": scan.scan_date.strftime("%Y-%m-%d %H:%M"),
                "timestamp": scan.scan_date.timestamp(), # For easier date filtering
                "details": {
                    "error_message": scan.error_message,
                    "pqc_algorithms": [s.strip() for s in scan.pqc_info.supported_suites.split(',')] if scan.pqc_info and scan.pqc_info.supported_suites else [],
                    "cipher_suites": [c.name for c in scan.cipher_suites] if scan.cipher_suites else [],
                    "certificate": {
                        "subject": scan.certificate.subject if scan.certificate else "Unknown",
                        "issuer": scan.certificate.issuer if scan.certificate else "Unknown",
                        "valid_from": scan.certificate.valid_from.strftime("%Y-%m-%d") if scan.certificate else "Unknown",
                        "valid_until": scan.certificate.valid_until.strftime("%Y-%m-%d") if scan.certificate else "Unknown",
                    }
                }
            })
        
        # Calculate averages/percentages
        pqc_adoption_rate = round((pqc_count / total_scans) * 100, 1)
        avg_score = round(total_score / total_scans, 1)
        commercial_ca_rate = round((commercial_ca_count / total_scans) * 100, 1)
        
        # Sort by date (descending) by default
        all_scans_data.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Prepare template context
        context = {
            "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_scans": total_scans,
            "pqc_count": pqc_count,
            "pqc_adoption_rate": pqc_adoption_rate,
            "avg_score": avg_score,
            "commercial_ca_rate": commercial_ca_rate,
            "grade_distribution": dict(grade_dist),
            "tls_distribution": dict(tls_dist),
            "pqc_algo_distribution": dict(pqc_algo_dist),
            "ca_distribution": dict(ca_dist),
            "cipher_distribution": dict(cipher_dist.most_common(10)),
            "geo_distribution": dict(geo_dist),
            "all_scans": all_scans_data
        }
        
        # Render template
        env = Environment(loader=FileSystemLoader("generator/templates"))
        template = env.get_template("index.html")
        output_html = template.render(context)
        
        # Write output
        output_path = os.path.join(output_dir, "index.html")
        with open(output_path, "w") as f:
            f.write(output_html)
            
        logger.info(f"Dashboard generated successfully at {output_path}")
        
    except Exception as e:
        logger.exception(f"Error generating dashboard: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    generate_dashboard()
