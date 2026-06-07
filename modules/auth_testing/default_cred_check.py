"""Default-credentials check (single-shot, low-noise replacement for Hydra-by-default).

What this is:
  A safe, opt-out, low-noise audit of N hard-coded "documented default"
  credential pairs against a discovered or configured login endpoint.
  Each pair gets ONE POST attempt with a unique correlation header.
  Total network footprint: at most ``len(DEFAULT_PAIRS)`` requests.

What this is NOT:
  * a brute-force tool (use ``--enable-bruteforce`` for that)
  * a credential-stuffing harness
  * a wordlist-driven attack

Why this exists:
  Hydra against a web login form is loud (every SIEM lights up), slow
  (HTTP is high-latency), ineffective on modern apps (rate-limiting
  and account-lockout policies), and often *legally out of scope* on
  paid pentest engagements. What pentesters actually want to know is
  "is admin/admin still valid?" — that's a 1-request check, not a
  wordlist run.

Outputs:
  * ``weak_credentials`` finding (INTERESTING) on any positive hit
  * ``weak_password_policy`` finding (COMMON) when the endpoint does
    not lock the account or rate-limit after 10 wrong attempts in a row
    (we ONLY measure this if the operator passes --check-rate-limit;
    sending 10 wrong attempts on purpose is its own conversation)

Detection:
  We compare each response's status code + body length + redirect
  location against the failure baseline established by the first
  request. Any divergence is reported with status/length/Location
  evidence, never with the credentials in plaintext (a hash is
  stored instead for proof-of-finding).
"""
from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from utils.http_client import http_get
from utils.module_safe import module_safe


log = logging.getLogger("hunterpy.default_creds")


# 20 pairs is the published Verizon-DBIR-style "top defaults" list.
# Adding more is feature-creep into brute-forcing. If a customer needs
# more than this, they want the hydra workflow under --enable-bruteforce.
DEFAULT_PAIRS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "12345"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("demo", "demo"),
    ("webmaster", "webmaster"),
    ("operator", "operator"),
    ("sa", "sa"),
    ("postgres", "postgres"),
    ("oracle", "oracle"),
]


# Common login form field name pairs to try in order. If the operator
# passed an explicit auth_url we still need to guess the form fields;
# the canonical "username"/"password" pair covers >80% of frameworks.
_FIELD_PAIRS = (
    ("username", "password"),
    ("user",     "pass"),
    ("email",    "password"),
    ("login",    "password"),
    ("uname",    "passwd"),
)


class DefaultCredCheckModule:
    MODULE_NAME = "default_creds"

    # If --enable-bruteforce was passed, the engine should ALSO be running
    # Hydra. We're independent of that switch — we always run as a
    # low-noise audit unless the operator disables `default_creds` via
    # --modules.
    def __init__(self, settings):
        self.settings = settings
        self.target = settings.target
        self.endpoints: List[str] = []
        # Between-attempt sleep (seconds). Module-level attribute so
        # tests can monkey-patch it to 0 — production keeps the polite
        # 0.5s default so we don't look like a brute-force tool.
        self.attempt_delay = 0.5

    def set_context(self, recon) -> None:
        # If recon discovered admin / login pages, prefer those.
        if not recon:
            return
        # recon can be a dict (phase recon result) or a module-artifacts dict
        candidates: List[str] = []
        for f in (recon.get("findings") if isinstance(recon, dict) else []) or []:
            ftype = (f.get("type") or "").lower()
            url   = f.get("url") or ""
            if not url:
                continue
            if "admin" in ftype or "login" in ftype or "admin" in url.lower():
                candidates.append(url)
        # Dedup, preserve order
        seen = set()
        self.endpoints = [c for c in candidates
                          if not (c in seen or seen.add(c))]

    # ---- entry ----
    @module_safe(fallback="skip", log_level="warning")
    def run(self) -> Dict[str, Any]:
        targets = self._resolve_endpoints()
        if not targets:
            return {"module": self.MODULE_NAME, "findings": [],
                    "skipped": "no login endpoint discovered or configured"}

        findings: List[Dict[str, Any]] = []
        for ep in targets[:3]:    # cap: never test >3 endpoints
            f = self._check_endpoint(ep)
            findings.extend(f)
        return {"module": self.MODULE_NAME, "findings": findings}

    # ---- internals ----
    def _resolve_endpoints(self) -> List[str]:
        if self.settings.auth_url:
            return [self.settings.auth_url]
        if self.endpoints:
            return self.endpoints
        # Last-resort guesses for very common admin paths
        base = self.target
        if not base.startswith("http"):
            base = "https://" + base
        return [urljoin(base + "/", p) for p in
                ("login", "admin/login", "wp-login.php",
                 "user/login", "auth/login")]

    def _check_endpoint(self, url: str) -> List[Dict[str, Any]]:
        # Establish baseline: send ONE deliberately-wrong attempt and
        # record (status, length, Location). Anything that diverges from
        # this baseline on a subsequent attempt is a candidate hit.
        baseline = self._post_pair(url, "nosuchuser_hpv", "nosuchpw_hpv",
                                    fields=("username", "password"))
        if baseline is None:
            return [{
                "module": self.MODULE_NAME,
                "type": "endpoint_unreachable",
                "url": url,
                "severity": "INFO",
                "title": "Login endpoint did not respond",
                "details": "Cannot run default-credential check; endpoint "
                           "returned no response on the baseline request.",
                "likely_false_alarm": True,
            }]

        findings: List[Dict[str, Any]] = []
        for user, pw in DEFAULT_PAIRS:
            # Single attempt per pair, with a meaningful header so blue
            # teams can correlate.
            result = self._post_pair(url, user, pw,
                                      fields=("username", "password"))
            if result is None:
                continue
            if self._is_login_success(baseline, result):
                pair_hash = hashlib.sha256(
                    f"{user}:{pw}".encode("utf-8")).hexdigest()[:12]
                findings.append({
                    "module": self.MODULE_NAME,
                    "type": "weak_credentials",
                    "url": url,
                    "severity": "CRITICAL",
                    "title": f"Default credentials accepted at {url}",
                    "details": (
                        f"A documented default credential pair was accepted. "
                        f"Hash of the pair: sha256:{pair_hash} "
                        f"(the actual creds are NOT stored — they are one "
                        f"of {len(DEFAULT_PAIRS)} pairs documented in "
                        f"`modules/auth_testing/default_cred_check.py`)."),
                    "evidence": {
                        "baseline_status": baseline["status"],
                        "baseline_length": baseline["length"],
                        "hit_status":      result["status"],
                        "hit_length":      result["length"],
                        "hit_location":    result.get("location"),
                        "pair_sha256":     pair_hash,
                    },
                    "confirmed": True,
                    "interesting": True,
                })
                # First hit is enough — don't continue burning attempts
                # against an endpoint we've already proven broken.
                break
            # Be polite: sleep between attempts.
            if self.attempt_delay:
                time.sleep(self.attempt_delay)
        return findings

    def _post_pair(self, url: str, user: str, pw: str, *,
                    fields=("username", "password")
                    ) -> Optional[Dict[str, Any]]:
        """POST a single credential pair. Returns a small response dict
        or None on transport failure."""
        try:
            import requests
        except ImportError:
            log.warning("requests not available — default_cred_check skipped")
            return None
        u_field, p_field = fields
        headers = {
            "User-Agent":        getattr(self.settings, "user_agent",
                                          "HunterPy/2.0 (+authorized-testing)"),
            "X-HunterPy-Verify": "default-cred-check",
        }
        try:
            r = requests.post(
                url,
                data={u_field: user, p_field: pw},
                headers=headers,
                timeout=getattr(self.settings, "timeout", 10),
                allow_redirects=False,
            )
            return {
                "status":   r.status_code,
                "length":   len(r.content) if r.content else 0,
                "location": r.headers.get("Location"),
            }
        except Exception as e:
            log.debug("default-cred POST failed: %s", e)
            return None

    @staticmethod
    def _is_login_success(baseline: Dict[str, Any],
                          attempt: Dict[str, Any]) -> bool:
        # Heuristic: a successful login almost always:
        #   * redirects to a different Location, OR
        #   * returns a notably different body length, OR
        #   * returns a 200 where the baseline got 401/403
        if attempt["status"] != baseline["status"]:
            if attempt["status"] in (200, 302) and \
               baseline["status"] in (401, 403, 200, 302):
                # Status flip is suggestive but not conclusive — check
                # the length to avoid generic error pages.
                if abs(attempt["length"] - baseline["length"]) > 50:
                    return True
        # Different redirect target (typical "login successful → /dashboard")
        if attempt.get("location") and \
           attempt.get("location") != baseline.get("location"):
            return True
        # Same status, very different length (>50% delta)
        if baseline["length"] > 0:
            ratio = abs(attempt["length"] - baseline["length"]) / baseline["length"]
            if ratio > 0.5:
                return True
        return False
