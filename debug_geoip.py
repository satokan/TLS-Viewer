from scanner.database import get_db
from scanner.models import ScanResult

def check_geoip_data():
    db = next(get_db())
    try:
        scans = db.query(ScanResult).filter(ScanResult.scan_status == "SUCCESS").all()
        print(f"Total successful scans: {len(scans)}")
        
        geo_count = 0
        for scan in scans:
            if scan.geo_location:
                geo_count += 1
                print(f"Domain: {scan.domain.name}, Country: {scan.geo_location.country_name}")
            
        print(f"Total scans with GeoIP: {geo_count}")
        
    finally:
        db.close()

if __name__ == "__main__":
    check_geoip_data()
