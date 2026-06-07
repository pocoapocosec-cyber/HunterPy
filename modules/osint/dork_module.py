"""HunterPy module: Google-dork generation (and optional scraping).

By default this module runs in **preview mode**: it renders the dork
template pack against the scan target and emits findings of type
`dork_suggestion` so the analyst can manually review them in Google
or paste them into the AI report.

Active scraping is opt-in via `settings.dorks_active = True` AND
`settings.confirm_dork_scraping = True`. Scraping Google is loud,
ToS-violating, and CAPTCHA-prone — the safe default is to never do it.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from utils.logger import ScanLogger
from modules.osint.dork_builder import DorkBuilder


log = logging.getLogger("hunterpy.dork_module")


# Per-template HunterPy severity mapping (kept conservative)
SEVERITY_TO_HP = {
    "critical": "CRITICAL", "high": "HIGH",
    "medium":   "MEDIUM",   "low": "LOW", "info": "INFO",
}


class DorkModule:
    MODULE_NAME = "dorks"

    def __init__(self, settings):
        self.settings = settings
        self.target = self._host(settings.target)
        self.logger = ScanLogger(settings.output_dir)
        self.builder = DorkBuilder()
        self.context: Dict[str, Any] = {}

    def set_context(self, recon: Dict[str, Any]) -> None:
        self.context = recon

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        only = getattr(self.settings, "dork_templates", None) or None
        extra = getattr(self.settings, "dork_extra", None) or None
        dork_set = self.builder.build(self.target, only=only, extra_keywords=extra)

        findings = self._preview_findings(dork_set)

        # Active scraping is OPT-IN ONLY
        if (getattr(self.settings, "dorks_active", False) and
            getattr(self.settings, "confirm_dork_scraping", False)):
            try:
                findings.extend(self._active_search(dork_set))
            except Exception as e:
                self.logger.log_error(f"[dorks] active search failed: {e}")
                findings.append({
                    "module": self.MODULE_NAME, "type": "dork_scrape_failed",
                    "url": self.target, "severity": "INFO",
                    "title": "Google scraping aborted",
                    "details": str(e),
                    "interesting": False,
                })

        return {
            "module":   self.MODULE_NAME,
            "findings": findings,
            "dorks":    dork_set.to_dict(),
        }

    # ------------------------------------------------------------------
    def _preview_findings(self, dork_set) -> List[Dict[str, Any]]:
        """One finding per template — a compact bundle the analyst can paste."""
        out: List[Dict[str, Any]] = []
        for template_name, dorks in dork_set.by_template().items():
            if not dorks:
                continue
            top = dorks[0]
            sev_hp = SEVERITY_TO_HP.get(top.severity, "INFO")
            queries = [d.query for d in dorks]
            urls    = [d.google_url for d in dorks]
            out.append({
                "module": self.MODULE_NAME,
                "type":   "dork_suggestion",
                "url":    top.google_url,
                "title":  f"Dork suggestions: {template_name} ({len(dorks)} queries)",
                "details": (f"{top.description}. "
                            "Open the URLs below in Google to review manually."),
                "severity": sev_hp,
                "evidence": {
                    "template":    template_name,
                    "description": top.description,
                    "queries":     queries,
                    "google_urls": urls,
                    "bing_urls":   [d.bing_url for d in dorks],
                    "ddg_urls":    [d.ddg_url  for d in dorks],
                    "mode": "preview",
                },
                # Always INTERESTING when severity is HIGH/CRITICAL,
                # otherwise leave to classifier defaults.
                "interesting": sev_hp in ("HIGH", "CRITICAL"),
            })
        return out

    # ------------------------------------------------------------------
    def _active_search(self, dork_set) -> List[Dict[str, Any]]:
        """Scrape Google (only when both opt-in flags are set)."""
        from utils.rate_limiter import RateLimiter
        from modules.osint.google_searcher import (
            CaptchaBlocked, GoogleSearcher,
        )

        max_per_query = int(getattr(self.settings, "dork_max_results", 10))
        rate = float(getattr(self.settings, "dork_rate_limit", 0.2))  # req/s
        max_queries = int(getattr(self.settings, "dork_max_queries", 5))
        limiter = RateLimiter(max_calls=1, period_sec=max(1.0, 1.0 / rate))

        searcher = GoogleSearcher(
            rate_limiter=limiter,
            proxy=getattr(self.settings, "proxy", None),
            timeout=self.settings.timeout,
            max_requests=max_queries * max_per_query,
        )

        out: List[Dict[str, Any]] = []
        processed = 0
        for d in dork_set.dorks[:max_queries]:
            processed += 1
            try:
                results = searcher.search(d.query, max_results=max_per_query)
            except CaptchaBlocked as e:
                self.logger.log_error(f"[dorks] {e}")
                out.append({
                    "module": self.MODULE_NAME, "type": "dork_scrape_blocked",
                    "url": d.google_url, "severity": "INFO",
                    "title": "Google CAPTCHA — scraping aborted",
                    "details": (f"Stopped after {processed} querie(s). "
                                "Switch back to preview mode or use a proxy."),
                })
                break

            for r in results:
                out.append({
                    "module": self.MODULE_NAME,
                    "type":   "dork_hit",
                    "url":    r.url,
                    "title":  f"Dork hit ({d.template}): {r.title[:80]}",
                    "details": r.description[:200],
                    "severity": SEVERITY_TO_HP.get(d.severity, "INFO"),
                    "evidence": {
                        "dork_query": d.query,
                        "template":   d.template,
                        "domain":     r.domain,
                        "discovered_at": r.timestamp,
                    },
                    "interesting": d.severity in ("critical", "high"),
                })
        return out

    # ------------------------------------------------------------------
    @staticmethod
    def _host(target: str) -> str:
        if "://" in target:
            from urllib.parse import urlparse
            return urlparse(target).netloc or target
        return target.rstrip("/")
