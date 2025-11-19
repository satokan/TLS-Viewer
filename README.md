# SSL/TLS Scanner

A system to scan and analyze SSL/TLS configurations for large domains, focusing on PQC adoption.

## Setup

1. Create virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Prerequisites

- Python 3.10+
- [pqcscan](https://github.com/pqcscan/pqcscan) (optional, for PQC detection)
  - Install `pqcscan` and ensure it's in your PATH.

## Usage

### 1. Run a Scan

To scan domains from `majestic_million.csv` (automatically downloaded) or a custom list:

```bash
# Default: Randomly sample 50 domains from majestic_million.csv
python run_scan.py

# Scan ALL domains in the CSV (WARNING: This takes a long time)
python run_scan.py --all

# Scan top 100 domains (no random sampling)
python run_scan.py --limit 100 --no-random

# Use a custom CSV file
python run_scan.py --input my_list.csv --all
```

This will:
- Download `majestic_million.csv` if missing (and no custom input provided).
- Perform scanning based on arguments.
- Save results to `scanner.db`.

### 2. Generate Dashboard

To generate the HTML dashboard:

```bash
python generator/main.py
```

The dashboard will be available at `output/index.html`.

## Project Structure

- `scanner/`: Core scanning logic (sslyze wrapper, PQC detection).
- `generator/`: Dashboard generation logic (HTML/JS/CSS).
- `data/`: GeoIP database (optional).
- `output/`: Generated dashboard files.

