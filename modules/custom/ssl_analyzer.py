"""SSL/TLS analyzer — certificate, ciphers, protocol versions."""
from __future__ import annotations

import datetime
import socket
import ssl
from typing import Any, Dict, List
from urllib.parse import urlparse

from utils.logger import ScanLogger


WEAK_CIPHERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5")


class SSLAnalyzer:
    MODULE_NAME = "ssl"

    def __init__(self, settings):
        self.settings = settings
        self.target = settings.target
        self.logger = ScanLogger(settings.output_dir)
        self.context: Dict[str, Any] = {}

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    def run(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []

        url = self.target if "://" in self.target else f"https://{self.target}"
        parsed = urlparse(url)
        if parsed.scheme == "http":
            findings.append({
                "module": self.MODULE_NAME, "type": "no_https", "url": url,
                "title": "Target does not use HTTPS", "severity": "HIGH",
                "details": "Site served over plain HTTP — traffic not encrypted",
                "interesting": True,
            })
            return {"module": self.MODULE_NAME, "findings": findings}

        host = parsed.hostname or self.target
        port = parsed.port or 443

        findings.extend(self._cert_checks(host, port, url))
        findings.extend(self._protocol_checks(host, port, url))
        return {"module": self.MODULE_NAME, "findings": findings}

    # ----------------------------------------------------------------
    def _cert_checks(self, host: str, port: int, url: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.settings.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    exp = datetime.datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days = (exp - datetime.datetime.utcnow()).days
                    if days < 0:
                        out.append({
                            "module": self.MODULE_NAME, "type": "cert_expired",
                            "url": url, "severity": "CRITICAL", "interesting": True,
                            "title": "SSL certificate expired",
                            "details": f"Certificate expired {abs(days)} days ago",
                            "raw": f"notAfter: {cert['notAfter']}",
                        })
                    elif days < 30:
                        out.append({
                            "module": self.MODULE_NAME, "type": "cert_expiring",
                            "url": url, "severity": "HIGH",
                            "title": f"SSL certificate expiring in {days} days",
                            "details": f"notAfter: {cert['notAfter']}",
                        })
                    issuer  = dict(x[0] for x in cert["issuer"])
                    subject = dict(x[0] for x in cert["subject"])
                    if issuer == subject:
                        out.append({
                            "module": self.MODULE_NAME, "type": "self_signed_cert",
                            "url": url, "severity": "HIGH", "interesting": True,
                            "title": "Self-signed SSL certificate",
                            "details": "Certificate not trusted by browsers",
                            "raw": f"issuer == subject: {issuer}",
                        })
                    cipher = tls.cipher()
                    if cipher:
                        name, proto, bits = cipher
                        for weak in WEAK_CIPHERS:
                            if weak in name:
                                out.append({
                                    "module": self.MODULE_NAME, "type": "weak_cipher",
                                    "url": url, "severity": "HIGH", "interesting": True,
                                    "title": f"Weak cipher suite: {name}",
                                    "details": f"Cipher {name}, protocol {proto}",
                                })
                                break
                        # ECDSA / ECDHE keys legitimately use 256/384 bits;
                        # only flag traditional RSA/DSA keys here.
                        is_ec = "ECDH" in name or "ECDSA" in name
                        if bits and bits < 2048 and not is_ec:
                            out.append({
                                "module": self.MODULE_NAME, "type": "weak_key_size",
                                "url": url, "severity": "HIGH", "interesting": True,
                                "title": f"Weak key size: {bits} bits",
                                "details": f"Key size {bits} < recommended 2048",
                            })
        except ssl.SSLCertVerificationError as e:
            out.append({
                "module": self.MODULE_NAME, "type": "cert_verification_failed",
                "url": url, "severity": "HIGH", "interesting": True,
                "title": "SSL certificate verification failed",
                "details": str(e),
            })
        except Exception as e:
            self.logger.log_error(f"ssl cert check failed: {e}")
        return out

    def _protocol_checks(self, host: str, port: int, url: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        candidates = []
        if hasattr(ssl, "PROTOCOL_TLSv1"):
            candidates.append(("TLSv1.0", ssl.PROTOCOL_TLSv1))
        if hasattr(ssl, "PROTOCOL_TLSv1_1"):
            candidates.append(("TLSv1.1", ssl.PROTOCOL_TLSv1_1))
        for label, const in candidates:
            try:
                ctx = ssl.SSLContext(const)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock):
                        out.append({
                            "module": self.MODULE_NAME, "type": "weak_protocol",
                            "url": url, "severity": "HIGH", "interesting": True,
                            "title": f"Weak TLS protocol supported: {label}",
                            "details": f"Server accepts deprecated {label}",
                        })
            except Exception:
                pass
        return out
