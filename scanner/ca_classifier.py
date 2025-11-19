from typing import Optional

class CAClassifier:
    """
    Classifies Certificate Authorities as Free or Commercial.
    """
    
    # Known free CA issuers
    FREE_CAS = {
        "Let's Encrypt",
        "ZeroSSL",
        "Buypass",
        "SSL.com Free",
        "cPanel",  # cPanel AutoSSL uses Let's Encrypt
        "R3",  # Let's Encrypt intermediate
        "R10", "R11",  # Let's Encrypt intermediates
        "E1", "E2",  # Let's Encrypt ECDSA intermediates
    }
    
    # Known commercial CA issuers
    COMMERCIAL_CAS = {
        "DigiCert",
        "GlobalSign",
        "Sectigo",
        "Comodo",
        "GeoTrust",
        "Thawte",
        "Entrust",
        "GoDaddy",
        "Network Solutions",
        "Symantec",
        "VeriSign",
        "RapidSSL",
        "AlphaSSL",
        "Certum",
        "SwissSign",
        "QuoVadis",
        "Amazon",  # Amazon Trust Services
        "Google Trust Services",
        "Microsoft",
        "Apple",
    }
    
    @classmethod
    def classify(cls, issuer: str) -> str:
        """
        Classify CA based on issuer string.
        
        Args:
            issuer: Certificate issuer DN string
            
        Returns:
            "FREE_CA", "COMMERCIAL_CA", or "UNKNOWN"
        """
        if not issuer:
            return "UNKNOWN"
        
        issuer_upper = issuer.upper()
        
        # Check for free CAs
        for ca in cls.FREE_CAS:
            if ca.upper() in issuer_upper:
                return "FREE_CA"
        
        # Check for commercial CAs
        for ca in cls.COMMERCIAL_CAS:
            if ca.upper() in issuer_upper:
                return "COMMERCIAL_CA"
        
        # Unknown CA
        return "UNKNOWN"
