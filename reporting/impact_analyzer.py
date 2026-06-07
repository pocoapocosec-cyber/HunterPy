"""Impact analyzer.

Translates a finding into:
  * priority_tier:  P1 / P2 / P3 / P4
  * suggested_sla:  hours/days to remediate
  * data_at_risk:   coarse category (credentials, source, PII, none, unknown)
  * compliance_hints: which regimes might care (PCI / HIPAA / GDPR / SOX / none)

Intentionally does NOT estimate dollar values — those numbers are
unfounded for a tool that doesn't know the target's business context.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class ImpactSummary:
    priority_tier: str = "P4"
    suggested_sla: str = "Best effort"
    data_at_risk: str = "unknown"
    compliance_hints: List[str] = field(default_factory=list)
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Map finding-type → data category
_DATA_AT_RISK = {
    "git_exposed":            "source code + git history",
    "env_exposed":            "credentials / secrets",
    "config_exposed":         "credentials / config",
    "sensitive_data_exposure":"credentials / secrets",
    "sensitive_keyword_in_js":"possible secrets in client code",
    "cors_with_credentials":  "authenticated session data",
    "cors_reflection":        "authenticated session data",
    "weak_cookie":            "session integrity",
    "weak_credentials":       "account compromise",
    "sql_injection":          "database contents",
    "admin_panel":            "administrative control",
    "cve":                    "depends on advisory — see references",
    "cert_expired":           "transport confidentiality",
    "weak_cipher":            "transport confidentiality",
    "no_https":               "all in-transit data",

    # Symfony intel-pack mappings (SECREP*)
    "symfony_profiler_exposed":     "credentials / secrets",
    "symfony_profiler_phpinfo":     "credentials / secrets",
    "symfony_profiler_lfi":         "source code + git history",
    "symfony_profiler_search":      "authenticated session data",
    "symfony_legacy_profiler":      "credentials / secrets",
    "symfony_legacy_parameters_yml":"credentials / secrets",
    "symfony_legacy_dev_front_controller": "credentials / config",
    "symfony_app_env_injection":    "credentials / config",
    "symfony_app_debug_injection":  "credentials / config",
    "symfony_exposed_credentials":  "credentials / secrets",
    "symfony_fragment_endpoint":    "administrative control",
    "imagemagick_vulnerable_version":"depends on advisory — see references",
    "eol_php_with_dangerous_functions":"depends on advisory — see references",
    "unrestricted_file_upload":     "administrative control",
}

# Coarse compliance hints — never definitive
_COMPLIANCE_HINTS = {
    "credentials / secrets":         ["PCI-DSS", "SOC2", "ISO27001"],
    "session integrity":             ["PCI-DSS"],
    "authenticated session data":    ["PCI-DSS", "GDPR"],
    "source code + git history":     ["SOC2"],
    "administrative control":        ["SOC2", "ISO27001"],
    "transport confidentiality":     ["PCI-DSS", "HIPAA", "GDPR"],
    "database contents":             ["PCI-DSS", "HIPAA", "GDPR"],
    "all in-transit data":           ["PCI-DSS", "HIPAA", "GDPR"],
}

# Severity-tier → priority tier + SLA
_TIER_BY_SEVERITY = {
    "CRITICAL": ("P1", "24 hours"),
    "HIGH":     ("P2", "72 hours"),
    "MEDIUM":   ("P3", "30 days"),
    "LOW":      ("P4", "Best effort / next release"),
    "INFO":     ("P4", "Informational"),
    "UNKNOWN":  ("P4", "Triage required"),
}


class ImpactAnalyzer:
    """Compute a non-monetary, defensible impact summary per finding."""

    def analyze(self, finding: Dict[str, Any]) -> ImpactSummary:
        sev = (finding.get("severity") or "INFO").upper()
        # If the classifier upgraded a low-severity finding via context
        # rules, prefer the classification tier.
        cls = finding.get("classification") or "COMMON"

        # Promote priority by one tier if classifier flagged INTERESTING
        # but the raw severity was only MEDIUM/LOW.
        priority, sla = _TIER_BY_SEVERITY.get(sev, _TIER_BY_SEVERITY["INFO"])
        if cls == "INTERESTING" and priority in ("P3", "P4"):
            priority = "P2"
            sla = "72 hours"

        data = _DATA_AT_RISK.get((finding.get("type") or "").lower(), "unknown")
        comp = list(_COMPLIANCE_HINTS.get(data, []))

        rationale_bits: List[str] = [f"severity={sev}", f"classification={cls}"]
        if finding.get("confirmed"):
            rationale_bits.append("confirmed=true")
        score = finding.get("score") or finding.get("risk_score")
        if score is not None:
            rationale_bits.append(f"score={score}")

        return ImpactSummary(
            priority_tier=priority,
            suggested_sla=sla,
            data_at_risk=data,
            compliance_hints=comp,
            rationale=", ".join(rationale_bits),
        )

    def analyze_many(self, findings: List[Dict[str, Any]]) -> Dict[str, ImpactSummary]:
        from reporting.poc_generator import _finding_key
        out: Dict[str, ImpactSummary] = {}
        for f in findings:
            out[_finding_key(f)] = self.analyze(f)
        return out
