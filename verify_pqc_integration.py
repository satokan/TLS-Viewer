import logging
import sys
from scanner.scanner import TLSScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def verify_pqc(domain: str):
    print(f"Verifying PQC integration for {domain}...")
    scanner = TLSScanner()
    result = scanner.scan_domain(domain)
    
    if result.scan_status != "SUCCESS":
        print(f"Scan failed: {result.error_message}")
        sys.exit(1)
        
    print(f"Scan Status: {result.scan_status}")
    
    pqc_info = result.pqc_info
    if not pqc_info:
        print("No PQC Info found in result.")
        sys.exit(1)
        
    print(f"PQC Supported: {pqc_info.is_supported}")
    print(f"Supported Suites: {pqc_info.supported_suites}")
    print(f"ML-KEM-512: {pqc_info.ml_kem_512}")
    print(f"ML-KEM-768: {pqc_info.ml_kem_768}")
    print(f"ML-KEM-1024: {pqc_info.ml_kem_1024}")
    
    if pqc_info.is_supported:
        print("SUCCESS: PQC support detected!")
    else:
        print("WARNING: PQC support NOT detected (this might be expected if the site doesn't support the specific groups we check).")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "pq.cloudflareresearch.com"
    verify_pqc(target)
