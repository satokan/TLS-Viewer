from scanner.database import get_db
from scanner.models import ScanResult, CipherSuite

def check_cipher_data():
    db = next(get_db())
    try:
        scans = db.query(ScanResult).filter(ScanResult.scan_status == "SUCCESS").all()
        print(f"Total successful scans: {len(scans)}")
        
        total_ciphers = 0
        for scan in scans:
            ciphers = scan.cipher_suites
            count = len(ciphers)
            print(f"Domain: {scan.domain.name}, Cipher Suites: {count}")
            if count > 0:
                print(f"  First cipher: {ciphers[0].name}")
            total_ciphers += count
            
        print(f"Total cipher suite entries: {total_ciphers}")
        
    finally:
        db.close()

if __name__ == "__main__":
    check_cipher_data()
