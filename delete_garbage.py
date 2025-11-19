from sqlalchemy.orm import Session
from scanner.database import get_db, engine
from scanner.models import Domain, ScanResult
from datetime import datetime

def delete_garbage():
    db: Session = next(get_db())
    
    domains_to_clean = ["youtube.com", "facebook.com", "google.com"]
    target_date_str = "2025-11-19"
    
    print(f"Cleaning up data for {domains_to_clean} on {target_date_str}...")
    
    deleted_count = 0
    
    for domain_name in domains_to_clean:
        domain = db.query(Domain).filter(Domain.name == domain_name).first()
        if not domain:
            continue
            
        # Find scans for this domain on the target date
        scans = db.query(ScanResult).filter(ScanResult.domain_id == domain.id).all()
        
        for scan in scans:
            # Check if scan date matches 2025-11-19
            if scan.scan_date.strftime("%Y-%m-%d") == target_date_str:
                print(f"Deleting scan for {domain_name} at {scan.scan_date} with grade {scan.grade}")
                db.delete(scan)
                deleted_count += 1
    
    db.commit()
    print(f"Deleted {deleted_count} records.")

if __name__ == "__main__":
    delete_garbage()
