import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sslyze import (
    ServerScanRequest,
    ServerNetworkLocation,
    Scanner,
    ScanCommand,
    ServerScanResult,
)
from sslyze.errors import ConnectionToServerFailed
from scanner.models import ScanResult, TLSVersion, CipherSuite, Certificate, PQCInfo
from scanner.pqc_scanner import PQCScanner
from scanner.ca_classifier import CAClassifier
from scanner.security_grader import SecurityGrader

# PQC Codepoints (IANA & Drafts)
# Based on https://github.com/google/boringssl/blob/master/include/openssl/nid.h and other sources
PQC_GROUPS = {
    0x6399: "X25519Kyber768Draft00",
    0x11EC: "ML-KEM-768",
    0x11ED: "X25519MLKEM768",
    0x023A: "Kyber512", 
    0x023C: "Kyber768",
    0x023E: "Kyber1024",
    # Add more as needed
}

logger = logging.getLogger(__name__)

class TLSScanner:
    def __init__(self):
        self.pqc_scanner = PQCScanner()
        if self.pqc_scanner.available:
            logger.info("PQC scanning enabled via pqcscan")
        else:
            logger.warning("PQC scanning disabled (pqcscan not available)")
    
    def scan_domain(self, domain: str) -> ScanResult:
        logger.info(f"Starting scan for {domain}")
        scan_start_time = datetime.now(timezone.utc)
        
        try:
            location = ServerNetworkLocation(hostname=domain, port=443)
            scan_request = ServerScanRequest(
                server_location=location,
                scan_commands=[
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                    ScanCommand.ELLIPTIC_CURVES,
                ],
            )
            
            scanner = Scanner()
            scanner.queue_scans([scan_request])
            
            # We only queued one scan, so we expect one result
            results = list(scanner.get_results())
            if not results:
                return self._create_error_result(domain, scan_start_time, "No results returned from scanner")
                
            result = results[0]
            
            if result.scan_status == "ERROR":
                return self._create_error_result(domain, scan_start_time, result.scan_error_message)
            
            if result.scan_result is None:
                return self._create_error_result(domain, scan_start_time, "Scan failed: No result returned (scan_result is None)")

            return self._parse_result(domain, scan_start_time, result.scan_result)

        except ConnectionToServerFailed as e:
            return self._create_error_result(domain, scan_start_time, f"Connection failed: {str(e)}")
        except Exception as e:
            logger.exception(f"Unexpected error scanning {domain}")
            return self._create_error_result(domain, scan_start_time, f"Unexpected error ({type(e).__name__}): {str(e)}")

    def _create_error_result(self, domain: str, scan_time: datetime, error_msg: str) -> ScanResult:
        return ScanResult(
            scan_date=scan_time,
            scan_status="ERROR",
            error_message=error_msg
        )

    def _parse_result(self, domain: str, scan_time: datetime, result: ServerScanResult) -> ScanResult:
        scan_result = ScanResult(
            scan_date=scan_time,
            scan_status="SUCCESS",
            tls_versions=[],
            cipher_suites=[],
        )

        # 1. TLS Versions & Cipher Suites
        self._parse_tls_versions_and_ciphers(result, scan_result)

        # 2. Certificate Info
        self._parse_certificate_info(result, scan_result)

        # 3. PQC Info (Prototype logic)
        self._parse_pqc_info(result, scan_result)
        
        # 4. Calculate Security Grade
        grade, score = SecurityGrader.calculate_grade(scan_result)
        scan_result.grade = grade
        scan_result.score = score

        return scan_result

    def _parse_tls_versions_and_ciphers(self, result: ServerScanResult, scan_result_model: ScanResult):
        # Mapping of ScanCommand to TLS version string
        version_map = {
            ScanCommand.SSL_2_0_CIPHER_SUITES: "SSL 2.0",
            ScanCommand.SSL_3_0_CIPHER_SUITES: "SSL 3.0",
            ScanCommand.TLS_1_0_CIPHER_SUITES: "TLS 1.0",
            ScanCommand.TLS_1_1_CIPHER_SUITES: "TLS 1.1",
            ScanCommand.TLS_1_2_CIPHER_SUITES: "TLS 1.2",
            ScanCommand.TLS_1_3_CIPHER_SUITES: "TLS 1.3",
        }

        for cmd, version_str in version_map.items():
            cmd_result = getattr(result, cmd.name.lower(), None)
            is_supported = False
            
            if cmd_result and cmd_result.status == "COMPLETED":
                # For TLS 1.3, it's 'accepted_cipher_suites' (list of AcceptedCipherSuite)
                # For others, it's 'accepted_cipher_suites' (list of CipherSuite)
                # sslyze 6.x unifies this a bit but let's check
                accepted = cmd_result.result.accepted_cipher_suites
                if accepted:
                    is_supported = True
                    for suite_entry in accepted:
                        # suite_entry is CipherSuite or AcceptedCipherSuite
                        suite = suite_entry.cipher_suite
                        
                        scan_result_model.cipher_suites.append(CipherSuite(
                            name=suite.name,
                            key_exchange=getattr(suite, "key_exchange", {}).get("name") if hasattr(suite, "key_exchange") else None, # sslyze object structure varies
                            # We might need to refine attribute access based on exact sslyze version objects
                            # For now, storing name is most critical
                            tls_version=version_str,
                            is_weak="NULL" in suite.name or "EXPORT" in suite.name or "RC4" in suite.name or "DES" in suite.name
                        ))

            scan_result_model.tls_versions.append(TLSVersion(
                version=version_str,
                is_supported=is_supported
            ))

    def _parse_certificate_info(self, result: ServerScanResult, scan_result_model: ScanResult):
        cert_result = result.certificate_info
        if cert_result and cert_result.status == "COMPLETED":
            deployments = cert_result.result.certificate_deployments
            if deployments:
                # Use the leaf certificate of the first deployment
                leaf_cert = deployments[0].received_certificate_chain[0]
                
                # Get certificate PEM
                from cryptography.hazmat.primitives import serialization
                cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                
                # Classify CA type
                issuer_str = str(leaf_cert.issuer)
                ca_type = CAClassifier.classify(issuer_str)
                
                scan_result_model.certificate = Certificate(
                    signature_algorithm=getattr(leaf_cert.signature_algorithm_oid, "_name", str(leaf_cert.signature_algorithm_oid)), 
                    public_key_algorithm=getattr(leaf_cert.public_key().algorithm_oid, "_name", str(leaf_cert.public_key().algorithm_oid)) if hasattr(leaf_cert.public_key(), "algorithm_oid") else "Unknown",
                    public_key_size=leaf_cert.public_key().key_size,
                    issuer=issuer_str,
                    subject=str(leaf_cert.subject),
                    ca_type=ca_type,
                    valid_from=leaf_cert.not_valid_before_utc,
                    valid_until=leaf_cert.not_valid_after_utc,
                    is_valid=True,  # Simplified validation
                    certificate_pem=cert_pem
                )

    def _parse_pqc_info(self, result: ServerScanResult, scan_result_model: ScanResult):
        """
        Parse PQC information using pqcscan if available.
        Falls back to NID-based detection (which doesn't work with current sslyze).
        """
        pqc_info = PQCInfo(
            is_supported=False,
            ml_kem_512=False,
            ml_kem_768=False,
            ml_kem_1024=False,
            supported_suites="",
            algorithm_combinations=""
        )
        
        # Try pqcscan first (preferred method)
        if self.pqc_scanner.available:
            try:
                # Extract domain from scan_result_model if available
                # For now, we'll need to pass domain separately or extract from result
                # Since we don't have domain here, we'll skip pqcscan in _parse_pqc_info
                # and call it separately in scan_domain
                pass
            except Exception as e:
                logger.error(f"pqcscan failed: {e}")
        
        # Fallback: Check elliptic curves (limited effectiveness with standard sslyze)
        curves_result = result.elliptic_curves
        if curves_result and curves_result.status == "COMPLETED":
            supported_curves = curves_result.result.supported_curves
            found_pqc_suites = []
            
            for curve in supported_curves:
                nid = getattr(curve, "openssl_nid", None)
                
                if nid in PQC_GROUPS:
                    pqc_info.is_supported = True
                    pqc_name = PQC_GROUPS[nid]
                    found_pqc_suites.append(pqc_name)
                    
                    if "Kyber512" in pqc_name or "ML-KEM-512" in pqc_name:
                        pqc_info.ml_kem_512 = True
                    if "Kyber768" in pqc_name or "ML-KEM-768" in pqc_name:
                        pqc_info.ml_kem_768 = True
                    if "Kyber1024" in pqc_name or "ML-KEM-1024" in pqc_name:
                        pqc_info.ml_kem_1024 = True

            if found_pqc_suites:
                pqc_info.supported_suites = ",".join(found_pqc_suites)
            
        scan_result_model.pqc_info = pqc_info
    
    def scan_domain_pqc(self, domain: str) -> PQCInfo:
        """
        Scan domain for PQC support using pqcscan.
        This is a separate method to be called after the main scan.
        """
        if not self.pqc_scanner.available:
            return PQCInfo(
                is_supported=False,
                ml_kem_512=False,
                ml_kem_768=False,
                ml_kem_1024=False,
                supported_suites="",
                algorithm_combinations=""
            )
        
        try:
            pqc_result = self.pqc_scanner.scan_domain(domain)
            
            # Map pqcscan results to PQCInfo model
            all_algos = pqc_result.hybrid_algos + pqc_result.pqc_algos
            
            pqc_info = PQCInfo(
                is_supported=pqc_result.pqc_supported,
                ml_kem_512=any("512" in algo for algo in all_algos),
                ml_kem_768=any("768" in algo for algo in all_algos),
                ml_kem_1024=any("1024" in algo for algo in all_algos),
                supported_suites=",".join(all_algos),
                algorithm_combinations=",".join(pqc_result.hybrid_algos)
            )
            
            return pqc_info
        except Exception as e:
            logger.exception(f"Error during PQC scan for {domain}: {e}")
            return PQCInfo(
                is_supported=False,
                ml_kem_512=False,
                ml_kem_768=False,
                ml_kem_1024=False,
                supported_suites="",
                algorithm_combinations=""
            )
