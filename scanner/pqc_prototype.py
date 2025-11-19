import sys
from sslyze import (
    ServerScanRequest,
    ServerNetworkLocation,
    Scanner,
    ScanCommand,
)

# PQC Codepoints (IANA & Drafts)
PQC_GROUPS = {
    0x6399: "X25519Kyber768Draft00",
    0x11EC: "ML-KEM-768",
    0x11ED: "X25519MLKEM768",
    0x023A: "Kyber512", # Example, needs verification
    0x023C: "Kyber768", # Example
    # Add more as needed
}

def scan_pqc(domain: str):
    print(f"Scanning {domain} for PQC support...")
    try:
        location = ServerNetworkLocation(hostname=domain, port=443)
        
        scan_request = ServerScanRequest(
            server_location=location,
            scan_commands=[ScanCommand.TLS_1_3_CIPHER_SUITES, ScanCommand.ELLIPTIC_CURVES],
        )
        
        scanner = Scanner()
        scanner.queue_scans([scan_request])
        
        for result in scanner.get_results():
            if result.scan_status == "ERROR":
                print(f"Error scanning {domain}: {result.scan_error_message}")
                continue
                
            # Check TLS 1.3 Cipher Suites
            tls13_result = result.scan_result.tls_1_3_cipher_suites
            if tls13_result.status == "COMPLETED":
                print("TLS 1.3 Cipher Suites:")
                for suite in tls13_result.result.accepted_cipher_suites:
                    print(f"  Cipher: {suite.cipher_suite.name}")
            
            # Check Supported Groups (Elliptic Curves)
            curves_result = result.scan_result.elliptic_curves
            if curves_result.status == "COMPLETED":
                print("\nSupported Groups (Curves):")
                for curve in curves_result.result.supported_curves:
                    print(f"  Curve: {curve.name} (NID: {curve.openssl_nid})")
                    
                    # Check if NID matches known PQC groups
                    # Note: This requires sslyze to recognize the group ID, which depends on the underlying OpenSSL.
            else:
                print(f"  Curves Scan Status: {curves_result.status}")

    except Exception as e:
        print(f"Exception: {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "pq.cloudflareresearch.com"
    scan_pqc(target)
