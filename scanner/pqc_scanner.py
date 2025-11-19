import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class PQCResult:
    pqc_supported: bool
    hybrid_algos: list[str]
    pqc_algos: list[str]
    nonpqc_algos: list[str]
    error: Optional[str] = None

class PQCScanner:
    def __init__(self, pqcscan_path: str = "~/.local/bin/pqcscan"):
        self.pqcscan_path = Path(pqcscan_path).expanduser()
        if not self.pqcscan_path.exists():
            logger.warning(f"pqcscan not found at {self.pqcscan_path}, PQC scanning will be disabled")
            self.available = False
        else:
            self.available = True
            logger.info(f"pqcscan found at {self.pqcscan_path}")
    
    def scan_domain(self, domain: str, port: int = 443, timeout: int = 30) -> PQCResult:
        """
        Scan a domain for PQC support using pqcscan.
        
        Args:
            domain: Domain name to scan
            port: Port number (default: 443)
            timeout: Timeout in seconds
            
        Returns:
            PQCResult with scan results
        """
        if not self.available:
            return PQCResult(
                pqc_supported=False,
                hybrid_algos=[],
                pqc_algos=[],
                nonpqc_algos=[],
                error="pqcscan not available"
            )
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name
            
            target = f"{domain}:{port}"
            cmd = [
                str(self.pqcscan_path),
                "tls-scan",
                "-t", target,
                "-o", output_file
            ]
            
            logger.debug(f"Running pqcscan: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                timeout=timeout,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"pqcscan failed with return code {result.returncode}: {result.stderr}")
                return PQCResult(
                    pqc_supported=False,
                    hybrid_algos=[],
                    pqc_algos=[],
                    nonpqc_algos=[],
                    error=f"pqcscan error: {result.stderr}"
                )
            
            # Parse JSON output
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            Path(output_file).unlink()  # Clean up temp file
            
            return self._parse_json_output(data)
            
        except subprocess.TimeoutExpired:
            logger.error(f"pqcscan timeout for {domain}")
            return PQCResult(
                pqc_supported=False,
                hybrid_algos=[],
                pqc_algos=[],
                nonpqc_algos=[],
                error="Timeout"
            )
        except Exception as e:
            logger.exception(f"Unexpected error during pqcscan: {e}")
            return PQCResult(
                pqc_supported=False,
                hybrid_algos=[],
                pqc_algos=[],
                nonpqc_algos=[],
                error=str(e)
            )
    
    def _parse_json_output(self, data: dict) -> PQCResult:
        """
        Parse pqcscan JSON output.
        
        Expected format:
        {
            "results": [
                {
                    "Tls": {
                        "pqc_supported": true,
                        "hybrid_algos": ["X25519MLKEM768"],
                        "pqc_algos": [],
                        "nonpqc_algos": [],
                        "error": null
                    }
                }
            ]
        }
        """
        try:
            results = data.get("results", [])
            if not results:
                return PQCResult(
                    pqc_supported=False,
                    hybrid_algos=[],
                    pqc_algos=[],
                    nonpqc_algos=[],
                    error="No results in pqcscan output"
                )
            
            # Get first result (we only scan one domain at a time)
            first_result = results[0]
            tls_data = first_result.get("Tls", {})
            
            return PQCResult(
                pqc_supported=tls_data.get("pqc_supported", False),
                hybrid_algos=tls_data.get("hybrid_algos", []),
                pqc_algos=tls_data.get("pqc_algos", []),
                nonpqc_algos=tls_data.get("nonpqc_algos", []),
                error=tls_data.get("error")
            )
        except Exception as e:
            logger.exception(f"Error parsing pqcscan output: {e}")
            return PQCResult(
                pqc_supported=False,
                hybrid_algos=[],
                pqc_algos=[],
                nonpqc_algos=[],
                error=f"Parse error: {str(e)}"
            )
