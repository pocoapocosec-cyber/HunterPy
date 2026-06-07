"""Target input validation. Blocks localhost, private ranges, and restricted TLDs."""
from __future__ import annotations

import ipaddress
import re

FORBIDDEN_TLDS = (".gov", ".mil")
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class TargetValidator:
    """Validate & sanitize a user-supplied target string."""

    def validate(self, target: str) -> str:
        target = (target or "").strip().lower()
        if not target:
            raise ValueError("Target cannot be empty.")

        # strip scheme if user passes a URL
        target = re.sub(r"^https?://", "", target)
        target = target.rstrip("/")

        if self._is_localhost(target):
            raise ValueError("Scanning localhost is not permitted.")
        if self._is_private_ip(target):
            raise ValueError("Scanning private IP ranges is not permitted.")
        if self._is_forbidden_tld(target):
            raise ValueError("Scanning government or military domains is not permitted.")
        if not (self._is_valid_domain(target) or self._is_valid_ip(target)):
            raise ValueError(f"'{target}' is not a valid domain or IP address.")
        return target

    @staticmethod
    def _is_localhost(t: str) -> bool:
        return t in ("localhost", "127.0.0.1", "::1")

    @staticmethod
    def _is_private_ip(t: str) -> bool:
        try:
            ip = ipaddress.ip_address(t)
            return any(ip in net for net in PRIVATE_RANGES)
        except ValueError:
            return False

    @staticmethod
    def _is_forbidden_tld(t: str) -> bool:
        return any(t.endswith(tld) for tld in FORBIDDEN_TLDS)

    @staticmethod
    def _is_valid_domain(t: str) -> bool:
        return bool(DOMAIN_REGEX.match(t))

    @staticmethod
    def _is_valid_ip(t: str) -> bool:
        try:
            ipaddress.ip_address(t)
            return True
        except ValueError:
            return False
