import logging
import sys
from scanner.manager import ScanManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scanner.log"),
        logging.StreamHandler()
    ]
)

def main():
    parser = argparse.ArgumentParser(description="Run SSL/TLS and PQC Scan")
    parser.add_argument("--input", default="majestic_million.csv", help="Input CSV file path")
    parser.add_argument("--limit", type=int, default=50, help="Number of domains to scan (default: 50)")
    parser.add_argument("--all", action="store_true", help="Scan ALL domains in the CSV (ignores --limit and --random)")
    parser.add_argument("--no-random", action="store_true", help="Disable random sampling (read from top)")
    parser.add_argument("--workers", type=int, default=5, help="Number of worker threads")
    
    args = parser.parse_args()
    
    csv_path = args.input
    target_csv = "scan_targets.csv"
    
    # Check if CSV exists, if not download it (only for default majestic_million.csv)
    import os
    import requests
    import random
    
    if csv_path == "majestic_million.csv" and not os.path.exists(csv_path):
        print(f"Downloading {csv_path}...")
        url = "http://downloads.majestic.com/majestic_million.csv"
        try:
            response = requests.get(url, stream=True)
            response.raise_for_status()
            with open(csv_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print("Download complete.")
        except Exception as e:
            print(f"Failed to download Majestic Million CSV: {e}")
            print("Please manually place 'majestic_million.csv' in the current directory.")
            return

    # Prepare target list
    if args.all:
        print(f"Scanning ALL domains from {csv_path}...")
        # Use the original CSV directly
        final_target_csv = csv_path
        limit = None
    else:
        # Sampling logic
        if args.no_random:
            print(f"Scanning top {args.limit} domains from {csv_path}...")
            # We can just pass the original CSV with a limit to ScanManager, 
            # but ScanManager.run_scan's limit applies to the loaded list.
            # Loader reads sequentially, so limit=N means top N.
            final_target_csv = csv_path
            limit = args.limit
        else:
            print(f"Sampling {args.limit} random domains from {csv_path}...")
            try:
                with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                    header = f.readline()
                    lines = f.readlines()
                    
                if not lines:
                    print("CSV file is empty.")
                    return
                    
                sampled_lines = random.sample(lines, min(args.limit, len(lines)))
                
                with open(target_csv, 'w', encoding='utf-8') as f:
                    f.write(header)
                    f.writelines(sampled_lines)
                    
                print(f"Created {target_csv} with {len(sampled_lines)} domains.")
                final_target_csv = target_csv
                limit = args.limit # Actually limit doesn't matter here as file is already limited, but good for safety
            except Exception as e:
                print(f"Error processing CSV: {e}")
                return

    manager = ScanManager(max_workers=args.workers)
    manager.run_scan(final_target_csv, limit=limit)

if __name__ == "__main__":
    main()
