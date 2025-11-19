import csv
import logging
from typing import List, Optional
from dataclasses import dataclass
import re

logger = logging.getLogger(__name__)

@dataclass
class DomainEntry:
    rank: int
    domain: str
    tld: str

class DomainLoader:
    def __init__(self):
        # Simple regex for domain validation
        self.domain_regex = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )

    def load_from_csv(self, file_path: str, limit: Optional[int] = None) -> List[DomainEntry]:
        """
        Load domains from Majestic Million CSV.
        Format: GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,...
        """
        domains = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                
                for row in reader:
                    if limit and len(domains) >= limit:
                        break
                        
                    if len(row) < 4:
                        continue
                        
                    try:
                        rank = int(row[0])
                        domain = row[2]
                        tld = row[3]
                        
                        if self.validate_domain(domain):
                            domains.append(DomainEntry(rank=rank, domain=domain, tld=tld))
                    except ValueError:
                        logger.warning(f"Invalid rank in row: {row}")
                        continue
                        
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            raise
            
        return self.deduplicate(domains)

    def validate_domain(self, domain: str) -> bool:
        return bool(self.domain_regex.match(domain))

    def deduplicate(self, domains: List[DomainEntry]) -> List[DomainEntry]:
        seen = set()
        unique_domains = []
        for d in domains:
            if d.domain not in seen:
                seen.add(d.domain)
                unique_domains.append(d)
        return unique_domains
