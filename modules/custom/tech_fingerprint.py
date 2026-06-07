"""Technology stack fingerprinter with NVD CVE enrichment."""
from __future__ import annotations

import logging
import re
import urllib.error
import urllib.request
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from modules.custom._nvd_client import CVE, NVDClient
from utils.logger import ScanLogger


log = logging.getLogger("hunterpy.tech_fingerprint")


HEADER_SIGS = {
    "x-powered-by":        "x_powered_by",
    "server":              "server",
    "x-generator":         "generator",
    "x-drupal-cache":      "drupal",
    # Symfony tells on itself via these debug headers — see SECREP1 +
    # SECREP-symfony-upstream-issues for the source.
    "x-debug-token":       "symfony_debug_token",
    "x-debug-token-link":  "symfony_debug_token_link",
    "x-symfony-cache":     "symfony_cache",
}

BODY_SIGS = [
    (re.compile(r"wp-content|wp-includes", re.I),   "WordPress"),
    (re.compile(r"Joomla!", re.I),                  "Joomla"),
    (re.compile(r"drupal-settings-json", re.I),     "Drupal"),
    (re.compile(r"__NEXT_DATA__", re.I),            "Next.js"),
    (re.compile(r"data-reactroot|react-dom", re.I), "React"),
    (re.compile(r"ng-version=", re.I),              "Angular"),
    (re.compile(r"window\.__NUXT__", re.I),         "Nuxt.js"),
    (re.compile(r"vue\.runtime|__vue__", re.I),     "Vue.js"),
    # Symfony body markers
    (re.compile(r"Symfony Profiler|sfWebDebugToolbar|symfony/skeleton", re.I),
                                                    "Symfony"),
]

KNOWN_PRODUCTS = (
    "apache", "nginx", "iis", "openssh", "lighttpd", "tomcat",
    "jetty", "php", "wordpress", "drupal", "joomla",
    "symfony", "imagemagick",
)


def _version_lt(a: str, b: str) -> bool:
    def parts(v):
        return [int(x) for x in re.findall(r"\d+", v)][:4]
    aa, bb = parts(a), parts(b)
    while len(aa) < len(bb): aa.append(0)
    while len(bb) < len(aa): bb.append(0)
    return aa < bb


def _extract_product_version(value: str) -> Optional[Tuple[str, str]]:
    if not value:
        return None
    m = re.search(
        r"(?P<prod>[a-z][a-z0-9._+-]*)\s*[/ ]\s*(?P<ver>\d+\.\d+(?:\.\d+)?)",
        value.lower(),
    )
    if not m:
        return None
    return m.group("prod"), m.group("ver")


class TechFingerprint:
    MODULE_NAME = "fingerprint"

    def __init__(self, settings, nvd_client: Optional[NVDClient] = None):
        self.settings = settings
        self.target = settings.target if "://" in settings.target \
                      else f"https://{settings.target}"
        self.logger = ScanLogger(settings.output_dir)
        self._nvd = nvd_client
        self.context: Dict[str, Any] = {}

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    # ---------- main ----------
    def run(self) -> Dict[str, Any]:
        status, headers, body = self._fetch(self.target)
        if status is None:
            return {"module": self.MODULE_NAME, "findings": [],
                    "technologies": [], "error": "unreachable"}

        tech: Dict[str, str] = {}
        for h, key in HEADER_SIGS.items():
            if h in headers:
                tech[key] = headers[h]

        frameworks = []
        for rx, name in BODY_SIGS:
            if rx.search(body or ""):
                frameworks.append(name)
        if frameworks:
            tech["frameworks"] = ",".join(sorted(set(frameworks)))

        findings: List[Dict[str, Any]] = [{
            "module": self.MODULE_NAME,
            "type": "tech_fingerprint",
            "url": self.target,
            "severity": "INFO",
            "title": "Technology fingerprint",
            "details": ", ".join(f"{k}={v}" for k, v in tech.items()) or "no signatures matched",
            "tech": tech,
        }]

        products = self._collect_products(tech)
        nvd_findings = self._nvd_enrich(products)
        findings.extend(nvd_findings)

        return {
            "module": self.MODULE_NAME,
            "findings": findings,
            "technologies": [f"{p} {v}" for p, v in products],
            "headers": headers,
        }

    # ---------- enrichment ----------
    @staticmethod
    def _collect_products(tech: Dict[str, str]) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        for src in (tech.get("server", ""), tech.get("x_powered_by", "")):
            pv = _extract_product_version(src)
            if not pv:
                continue
            product, version = pv
            if not any(known in product for known in KNOWN_PRODUCTS):
                continue
            if (product, version) not in out:
                out.append((product, version))
        return out

    def _nvd_enrich(self, products: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
        if not products or not self.settings.nvd_enabled:
            return []
        client = self._nvd or NVDClient(
            api_key=self.settings.nvd_api_key,
            db_path=self.settings.db_path,
            cache_ttl=timedelta(days=self.settings.nvd_cache_days),
            offline=self.settings.nvd_offline,
        )
        out: List[Dict[str, Any]] = []
        seen: set = set()
        for product, version in products:
            try:
                cves = client.lookup_product(
                    product, version,
                    limit=self.settings.nvd_max_per_product,
                    min_cvss=self.settings.nvd_min_cvss,
                )
            except Exception as e:
                log.warning("nvd lookup failed for %s %s: %s", product, version, e)
                continue
            for cve in cves:
                if cve.cve_id in seen:
                    continue
                seen.add(cve.cve_id)
                out.append(self._cve_to_finding(product, version, cve))
        return out

    @staticmethod
    def _cve_to_finding(product: str, version: str, cve: CVE) -> Dict[str, Any]:
        desc = cve.description or f"{product} {version} affected by {cve.cve_id}"
        return {
            "module": "fingerprint",
            "type": "cve",
            "url": product,
            "severity": cve.severity.upper() if cve.severity else "HIGH",
            "title": f"{cve.cve_id} ({cve.severity}) affects {product} {version}",
            "details": desc[:400],
            "cvss": cve.cvss,
            "confirmed": False,
            "interesting": cve.cvss >= 7.0,
            "evidence": {
                "product": product, "version": version,
                "cve_id": cve.cve_id, "cwe_ids": cve.cwe_ids,
                "references": cve.references, "source": cve.source,
            },
        }

    # ---------- HTTP ----------
    def _fetch(self, url: str):
        req = urllib.request.Request(url, headers={
            "User-Agent": self.settings.user_agent,
        })
        try:
            with urllib.request.urlopen(req, timeout=self.settings.timeout) as r:
                lower = {k.lower(): v for k, v in r.headers.items()}
                return r.status, lower, r.read(200_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            lower = {k.lower(): v for k, v in (e.headers or {}).items()}
            return e.code, lower, ""
        except Exception:
            return None, {}, ""
