import boto3
import os
import logging
from datetime import datetime
from decimal import Decimal
import json
from typing import Any

from scanner.models import ScanResult

logger = logging.getLogger(__name__)

class DynamoDBManager:
    def __init__(self, table_name: str = None):
        self.table_name = table_name or os.getenv("TABLE_NAME")
        if not self.table_name:
            raise ValueError("TABLE_NAME environment variable is not set")
        
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(self.table_name)

    def save_result(self, scan_result: ScanResult):
        """Save a ScanResult object to DynamoDB."""
        try:
            item = self._to_dynamo_item(scan_result)
            self.table.put_item(Item=item)
            logger.info(f"Saved result for {scan_result.domain.name} to DynamoDB")
        except Exception as e:
            logger.error(f"Failed to save result to DynamoDB: {e}")
            raise

    def _to_dynamo_item(self, result: ScanResult) -> dict:
        """Convert ScanResult to a DynamoDB-compatible dictionary."""
        
        # Base fields
        item = {
            "domain": result.domain.name,
            "scan_date": result.scan_date.isoformat(),
            "scan_status": result.scan_status,
            "score": Decimal(str(result.score)) if result.score is not None else None,
            "grade": result.grade,
            "error_message": result.error_message,
            "timestamp": Decimal(str(result.scan_date.timestamp()))
        }

        # PQC Info
        if result.pqc_info:
            item["pqc_info"] = {
                "is_supported": result.pqc_info.is_supported,
                "supported_suites": result.pqc_info.supported_suites,
                "notes": result.pqc_info.notes
            }

        # Certificate
        if result.certificate:
            item["certificate"] = {
                "common_name": result.certificate.common_name,
                "issuer": result.certificate.issuer,
                "valid_from": result.certificate.valid_from.isoformat() if result.certificate.valid_from else None,
                "valid_until": result.certificate.valid_until.isoformat() if result.certificate.valid_until else None,
                "is_valid": result.certificate.is_valid,
                "signature_algorithm": result.certificate.signature_algorithm,
                "ca_type": result.certificate.ca_type,
                "subject": result.certificate.subject,
                # PEM might be too large, but let's include it for now or skip it
                # "certificate_pem": result.certificate.certificate_pem 
            }

        # TLS Versions
        if result.tls_versions:
            item["tls_versions"] = [
                {"version": v.version, "is_supported": v.is_supported}
                for v in result.tls_versions
            ]

        # Cipher Suites
        if result.cipher_suites:
            item["cipher_suites"] = [
                {"name": c.name, "protocol_version": c.protocol_version}
                for c in result.cipher_suites
            ]

        # Geo Location
        if result.geo_location:
            item["geo_location"] = {
                "country_code": result.geo_location.country_code,
                "country_name": result.geo_location.country_name,
                "city": result.geo_location.city,
                "ip_address": result.geo_location.ip_address
            }

        # Remove None values (DynamoDB doesn't like them sometimes, or just cleaner)
        return self._clean_item(item)

    def _clean_item(self, item: Any) -> Any:
        """Recursively remove None values and convert floats to Decimals."""
        if isinstance(item, dict):
            return {k: self._clean_item(v) for k, v in item.items() if v is not None}
        elif isinstance(item, list):
            return [self._clean_item(v) for v in item]
        elif isinstance(item, float):
            return Decimal(str(item))
        else:
            return item
