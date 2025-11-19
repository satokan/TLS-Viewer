from typing import List
from scanner.models import ScanResult, TLSVersion, CipherSuite, PQCInfo


class SecurityGrader:
    """
    Calculate security grade and score for TLS/SSL configurations.
    
    Grading criteria:
    - S (Safe & Future-proof): TLS 1.3 + PQC Hybrid + No Weak Ciphers
    - A (Safe): TLS 1.2/1.3 + Strong Ciphers
    - B (Acceptable): TLS 1.2 + Weak Ciphers (No Critical)
    - F (Insecure): SSL 3.0/TLS 1.0/1.1 or Critical Vulnerabilities
    """
    
    WEAK_CIPHER_KEYWORDS = {
        "NULL", "EXPORT", "RC4", "DES", "MD5", "ANON"
    }
    
    DEPRECATED_TLS_VERSIONS = {
        "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"
    }
    
    @classmethod
    def calculate_grade(cls, scan_result: ScanResult) -> tuple[str, float]:
        """
        Calculate security grade and score.
        
        Args:
            scan_result: Scan result with TLS versions, cipher suites, and PQC info
            
        Returns:
            Tuple of (grade: str, score: float)
            Grade is one of: "S", "A", "B", "F"
            Score is 0-100
        """
        score = 100.0
        
        # Get supported TLS versions
        supported_versions = [v.version for v in scan_result.tls_versions if v.is_supported]
        
        # Check for deprecated/insecure protocols
        has_deprecated = any(v in cls.DEPRECATED_TLS_VERSIONS for v in supported_versions)
        has_tls12 = "TLS 1.2" in supported_versions
        has_tls13 = "TLS 1.3" in supported_versions
        
        # Check cipher suites
        weak_ciphers = [c for c in scan_result.cipher_suites if c.is_weak]
        has_weak_ciphers = len(weak_ciphers) > 0
        
        # Check PQC support
        has_pqc = scan_result.pqc_info and scan_result.pqc_info.is_supported
        
        # Grading logic
        if has_deprecated:
            # F grade for deprecated protocols
            score -= 60
            grade = "F"
        elif has_tls13 and has_pqc and not has_weak_ciphers:
            # S grade: Future-proof
            grade = "S"
            score = 100.0
        elif (has_tls12 or has_tls13) and not has_weak_ciphers:
            # A grade: Secure
            grade = "A"
            score = 95.0
            if not has_tls13:
                score -= 5  # Slight penalty for no TLS 1.3
        elif has_tls12 and has_weak_ciphers:
            # B grade: Acceptable but has weaknesses
            grade = "B"
            score = 70.0
            score -= len(weak_ciphers) * 2  # Penalty for each weak cipher
        else:
            # F grade: Insecure
            grade = "F"
            score = 40.0
        
        # Additional scoring adjustments
        if has_pqc and grade in ["A", "B"]:
            score += 5  # Bonus for PQC support
        
        # Ensure score is in valid range
        score = max(0.0, min(100.0, score))
        
        return (grade, score)
