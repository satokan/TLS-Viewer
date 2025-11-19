import logging
import sys
from scanner.scanner import TLSScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_hybrid_scanner(domain: str):
    print(f"Testing hybrid scanner (sslyze + pqcscan) for {domain}...")
    scanner = TLSScanner()
    
    # 1. Main TLS scan
    print("\n=== Phase 1: Standard TLS/SSL Scan (sslyze) ===")
    result = scanner.scan_domain(domain)
    
    if result.scan_status != "SUCCESS":
        print(f"Scan failed: {result.error_message}")
        sys.exit(1)
        
    print(f"Scan Status: {result.scan_status}")
    print(f"TLS Versions: {[v.version for v in result.tls_versions if v.is_supported]}")
    print(f"Cipher Suites: {len(result.cipher_suites)} found")
    
    if result.certificate:
        print(f"\nCertificate:")
        print(f"  Subject: {result.certificate.subject}")
        print(f"  Issuer: {result.certificate.issuer}")
        print(f"  Algorithm: {result.certificate.signature_algorithm}")
        print(f"  Key Size: {result.certificate.public_key_size} bits")
        print(f"  Valid: {result.certificate.valid_from} to {result.certificate.valid_until}")
        if result.certificate.certificate_pem:
            print(f"  PEM: {result.certificate.certificate_pem[:100]}...")
    
    # 2. PQC scan
    print("\n=== Phase 2: PQC Scan (pqcscan) ===")
    pqc_info = scanner.scan_domain_pqc(domain)
    
    print(f"PQC Supported: {pqc_info.is_supported}")
    print(f"Supported Suites: {pqc_info.supported_suites}")
    print(f"Hybrid Algorithms: {pqc_info.algorithm_combinations}")
    print(f"ML-KEM-512: {pqc_info.ml_kem_512}")
    print(f"ML-KEM-768: {pqc_info.ml_kem_768}")
    print(f"ML-KEM-1024: {pqc_info.ml_kem_1024}")
    
    if pqc_info.is_supported:
        print("\n✓ SUCCESS: PQC support detected via pqcscan!")
    else:
        print("\n✗ No PQC support detected (expected for most sites)")
    
    print("\n=== Test Complete ===")

if __name__ == "__main__":
    # Test with PQC-enabled site
    test_hybrid_scanner("pq.cloudflareresearch.com")
    
    print("\n" + "="*60)
    
    # Test with normal site
    test_hybrid_scanner("google.com")
