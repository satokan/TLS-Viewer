import geoip2.database
import logging
import os
from typing import Optional
from scanner.models import GeoLocation
import socket

logger = logging.getLogger(__name__)

class GeoIPResolver:
    def __init__(self, db_path: str = "./data/GeoLite2-City.mmdb"):
        self.db_path = db_path
        self.reader = None
        if os.path.exists(db_path):
            try:
                self.reader = geoip2.database.Reader(db_path)
            except Exception as e:
                logger.error(f"Failed to open GeoIP database: {e}")
        else:
            logger.warning(f"GeoIP database not found at {db_path}. GeoIP resolution will be disabled.")

    def resolve(self, domain: str) -> Optional[GeoLocation]:
        if not self.reader:
            return None

        try:
            # Resolve domain to IP
            ip_address = socket.gethostbyname(domain)
            
            # Lookup IP
            response = self.reader.city(ip_address)
            
            return GeoLocation(
                ip_address=ip_address,
                country_code=response.country.iso_code,
                country_name=response.country.name,
                region=response.subdivisions.most_specific.name if response.subdivisions else None,
                city=response.city.name,
                latitude=response.location.latitude,
                longitude=response.location.longitude
            )
        except socket.gaierror:
            logger.warning(f"Could not resolve IP for domain: {domain}")
            return None
        except geoip2.errors.AddressNotFoundError:
            logger.warning(f"IP address not found in GeoIP database: {ip_address}")
            return None
        except Exception as e:
            logger.error(f"Error resolving GeoIP for {domain}: {e}")
            return None

    def close(self):
        if self.reader:
            self.reader.close()
