from scanner.database import get_db
from scanner.models import Domain, ScanResult

def verify_db():
    db = next(get_db())
    try:
        domains = db.query(Domain).all()
        print(f"Found {len(domains)} domains in DB:")
        for d in domains:
            print(f"- {d.name} (Rank: {d.global_rank})")
            for r in d.scan_results:
                print(f"  - Scan Date: {r.scan_date}, Status: {r.scan_status}")
                if r.certificate:
                    print(f"    - Cert: {r.certificate.signature_algorithm}, Key: {r.certificate.public_key_algorithm} ({r.certificate.public_key_size} bits)")
                print(f"    - TLS Versions: {[v.version for v in r.tls_versions if v.is_supported]}")
                print(f"    - Cipher Suites: {len(r.cipher_suites)} found")
                if r.pqc_info:
                    print(f"    - PQC Supported: {r.pqc_info.is_supported}")
                    print(f"    - PQC Suites: {r.pqc_info.supported_suites}")

    finally:
        db.close()

if __name__ == "__main__":
    verify_db()
