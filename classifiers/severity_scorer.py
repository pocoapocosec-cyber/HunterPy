"""Severity scorer — produces a 0–10 risk score per finding.

Folds together the static severity, type-based boost, path heuristics,
and (optionally) confidence. Designed so the FindingClassifier can
make its FALSE_ALARM / COMMON / INTERESTING decision off a single
normalized score.
"""
from __future__ import annotations

from typing import Any, Dict


SEVERITY_BASE = {
    "CRITICAL": 9.0,
    "HIGH":     7.0,
    "MEDIUM":   5.0,
    "LOW":      2.0,
    "INFO":     0.5,
    "UNKNOWN":  1.0,
}

HIGH_VALUE_TYPE_BOOSTS = {
    "sql_injection":            2.0,
    "cors_misconfiguration":    1.5,
    "sensitive_data_exposure":  2.0,
    "weak_credentials":         2.0,
    "hash_cracked":             1.5,
    "admin_panel":              1.5,
    "git_exposed":              2.0,
    "env_exposed":              2.0,
    "source_map_exposed":       0.5,
    "graphql_endpoint":         0.5,
    "file_upload":              1.0,
    "cve":                      1.5,
}

HIGH_INTEREST_PATHS = (
    "admin", ".git", ".env", "backup", "config",
    "upload", "shell", "phpinfo", "debug", "phpmyadmin",
)


class SeverityScorer:
    """0–10 numeric score for a finding dict."""

    def score(self, finding: Dict[str, Any]) -> float:
        sev = (finding.get("severity") or "INFO").upper()
        base = SEVERITY_BASE.get(sev, 1.0)

        # type-based boost
        ftype = (finding.get("type") or "").lower()
        for key, boost in HIGH_VALUE_TYPE_BOOSTS.items():
            if key in ftype:
                base += boost
                break

        # path-based boost
        path = (finding.get("path") or finding.get("url") or "").lower()
        if any(p in path for p in HIGH_INTEREST_PATHS):
            base += 1.0

        # CVSS, if reported directly (e.g. from NVD)
        cvss = float(finding.get("cvss") or 0.0)
        if cvss >= 9.0:
            base += 1.5
        elif cvss >= 7.0:
            base += 1.0
        elif cvss >= 4.0:
            base += 0.5

        # confirmed findings get a small bump
        if finding.get("confirmed"):
            base += 0.5

        return round(min(10.0, max(0.0, base)), 2)
