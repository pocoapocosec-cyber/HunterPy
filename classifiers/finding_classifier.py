"""Three-tier finding classifier.

Classifies each finding as FALSE_ALARM | COMMON | INTERESTING using:
  1. Module-supplied hints (`likely_false_alarm`, `confirmed`, `interesting`)
  2. Numeric severity score from SeverityScorer
  3. Pattern matches (false-alarm + interesting signature packs)
  4. Cross-finding context rules
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from classifiers.severity_scorer import SeverityScorer


SIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "signatures")


def _load(name: str) -> Dict[str, Any]:
    try:
        with open(os.path.join(SIG_DIR, name), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


_FP_PACK         = _load("common_fps.json").get("patterns", [])
_INTERESTING_PACK = _load("interesting_patterns.json").get("patterns", [])


# ----- hard-coded type maps from the spec --------------------------------
FALSE_ALARM_TYPES = {
    "nikto_osvdb_0", "server_banner", "options_method", "daytime_connection",
    "robots_txt", "favicon_ico", "sitemap_xml", "404_redirect",
    "hsts_short_max_age", "hsts_no_subdomains",
    "x_xss_protection_missing", "referrer_policy_missing",
    "permissions_policy_missing",
}

COMMON_TYPES = {
    "missing_security_header", "info_disclosure_header", "directory_found",
    "missing_csp", "server_version_disclosed",
    "x_powered_by_disclosed", "missing_x_frame_options", "missing_hsts",
    "directory_listing", "http_methods_allowed", "weak_password_policy",
    "default_error_pages", "outdated_software", "backup_file_found",
    "ffuf_directory", "weak_hsts",
    "dork_suggestion",           # preview-mode dork bundle
    "dork_scrape_blocked",       # informational — Google blocked us
    "dork_scrape_failed",        # informational — generic scrape failure
}

INTERESTING_TYPES = {
    "sql_injection", "cors_misconfiguration", "cors_with_credentials",
    "sensitive_data_exposure", "admin_panel", "git_exposed", "env_exposed",
    "graphql_endpoint", "source_map_exposed", "weak_credentials",
    "hash_cracked", "cert_expired", "self_signed_cert", "weak_cipher",
    "weak_key_size", "weak_protocol", "no_https",
    "cors_null_origin", "cors_reflection", "cve", "ffuf_vhost",
    "dork_hit",                  # actual scrape hit — real attack surface

    # Symfony intel-pack finding types (see signatures/intel/symfony_exposure.json
    # and docs/threat-intel/SECREP-*.pdf for the source incidents).
    "symfony_profiler_exposed",
    "symfony_profiler_phpinfo",
    "symfony_profiler_lfi",
    "symfony_profiler_search",
    "symfony_legacy_dev_front_controller",
    "symfony_legacy_profiler",
    "symfony_legacy_parameters_yml",
    "symfony_fragment_endpoint",
    "symfony_app_env_injection",
    "symfony_app_debug_injection",
    "symfony_exposed_credentials",
    "eol_php_with_dangerous_functions",
    "imagemagick_vulnerable_version",
    "unrestricted_file_upload",
}


class FindingClassifier:
    """Apply classification tags to a list of findings."""

    def __init__(self) -> None:
        self.scorer = SeverityScorer()
        self._all: List[Dict[str, Any]] = []

    # ---------- public API ----------
    def classify_all(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        self._all = findings
        return [self.classify(f) for f in findings]

    def classify(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        # Each step appends to `factors` so the final stamp can show a
        # full audit trail of WHY the classification landed where it did.
        # This is what auditors / clients ask for when they need to
        # justify a P0 vs P3 call.
        factors: List[Dict[str, Any]] = []
        cls, conf, reason = self._classify_core(finding, factors)
        cls, conf, reason = self._apply_context(finding, cls, conf, reason, factors)
        return self._stamp(finding, cls, conf, reason, factors)

    # ---------- core decision ----------
    def _classify_core(self, f: Dict[str, Any],
                       factors: List[Dict[str, Any]]) -> Tuple[str, float, str]:
        # 1) explicit module hints win first
        if f.get("likely_false_alarm"):
            factors.append({"kind": "module_hint",
                            "field": "likely_false_alarm",
                            "weight": -1.0,
                            "note": "module said this is a likely FP"})
            return "FALSE_ALARM", 0.9, "module flagged as likely false alarm"
        if f.get("confirmed"):
            factors.append({"kind": "module_hint", "field": "confirmed",
                            "weight": +1.0,
                            "note": "module confirmed the finding"})
            return "INTERESTING", 0.95, "module confirmed the finding"
        if f.get("interesting"):
            factors.append({"kind": "module_hint", "field": "interesting",
                            "weight": +0.8,
                            "note": "module flagged as interesting"})
            return "INTERESTING", 0.85, "module flagged as interesting"

        ftype = (f.get("type") or "").lower()
        if ftype in FALSE_ALARM_TYPES:
            factors.append({"kind": "type_table",
                            "table": "FALSE_ALARM_TYPES",
                            "value": ftype, "weight": -0.8})
            return "FALSE_ALARM", 0.85, f"known false-alarm type: {ftype}"
        if ftype in INTERESTING_TYPES:
            factors.append({"kind": "type_table",
                            "table": "INTERESTING_TYPES",
                            "value": ftype, "weight": +0.8})
            return "INTERESTING", 0.85, f"known high-value type: {ftype}"
        if ftype in COMMON_TYPES:
            score = self.scorer.score(f)
            f["score"] = score
            factors.append({"kind": "type_table",
                            "table": "COMMON_TYPES",
                            "value": ftype, "weight": +0.2})
            factors.append({"kind": "severity_score", "score": score,
                            "weight": min(score / 10.0, 1.0)})
            if score >= 8.0:
                return "INTERESTING", 0.8, f"common type promoted by score: {score}"
            return "COMMON", 0.75, f"known common type: {ftype}"

        # 2) signature-pack matches
        fp_match = self._matched_pack_entry(f, _FP_PACK)
        if fp_match is not None:
            factors.append({"kind": "signature_pack",
                            "pack": "common_fps.json",
                            "matched_entry": fp_match, "weight": -0.8})
            return "FALSE_ALARM", 0.8, "matched false-positive signature pack"
        int_match = self._matched_pack_entry(f, _INTERESTING_PACK)
        if int_match is not None:
            factors.append({"kind": "signature_pack",
                            "pack": "interesting_patterns.json",
                            "matched_entry": int_match, "weight": +0.8})
            return "INTERESTING", 0.85, "matched interesting signature pack"

        # 3) numeric score fallback
        score = self.scorer.score(f)
        f["score"] = score
        factors.append({"kind": "severity_score", "score": score,
                        "weight": min(score / 10.0, 1.0),
                        "note": "no type/signature match — score-only decision"})
        if score >= 7.0:
            return "INTERESTING", min(score / 10.0, 0.95), f"high severity score: {score}"
        if score >= 3.0:
            return "COMMON", 0.7, f"medium severity score: {score}"
        return "FALSE_ALARM", 0.6, f"low severity score: {score}"

    # ---------- signature pack helpers ----------
    @classmethod
    def _matches_pack(cls, f: Dict[str, Any], pack: List[Dict[str, Any]]) -> bool:
        """Back-compat thin wrapper — most callers only need a bool."""
        return cls._matched_pack_entry(f, pack) is not None

    @staticmethod
    def _matched_pack_entry(f: Dict[str, Any],
                             pack: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Return the matching entry (for explainability) or None."""
        haystack = " ".join(str(x) for x in (
            f.get("title", ""), f.get("description", ""),
            f.get("details", ""), f.get("url", ""), f.get("type", "")
        )).lower()
        for entry in pack:
            match = entry.get("match", entry)
            contains = match.get("contains") if isinstance(match, dict) else None
            regex    = match.get("regex")    if isinstance(match, dict) else None
            module   = match.get("module")   if isinstance(match, dict) else None
            if module and (f.get("module") or "").lower() != module.lower():
                continue
            if contains and contains.lower() not in haystack:
                continue
            if regex and not re.search(regex, haystack, re.I):
                continue
            if contains or regex or module:
                return {
                    "id":       entry.get("id"),
                    "contains": contains,
                    "regex":    regex,
                    "module":   module,
                }
        return None

    # ---------- context rules ----------
    def _apply_context(self, f: Dict[str, Any], cls: str,
                       conf: float, reason: str,
                       factors: List[Dict[str, Any]]) -> Tuple[str, float, str]:
        ftype = (f.get("type") or "").lower()

        # Backup file alongside admin panel → upgrade
        if ("backup" in ftype or "backup" in (f.get("url") or "").lower()):
            if any("admin" in (g.get("type") or "").lower()
                   or "admin" in (g.get("url") or "").lower()
                   for g in self._all):
                factors.append({"kind": "context_rule",
                                "rule": "backup_with_admin",
                                "weight": +0.5})
                return "INTERESTING", 0.85, "backup file found alongside admin path"

        # Directory listing + confirmed SQLi anywhere → upgrade
        if "directory" in ftype:
            if any((g.get("type") or "").lower() == "sql_injection"
                   for g in self._all):
                factors.append({"kind": "context_rule",
                                "rule": "directory_with_sqli",
                                "weight": +0.5})
                return "INTERESTING", 0.8, "directory access on SQL-injectable target"

        # Outdated server banner with known-vulnerable software
        if ftype == "info_disclosure_header":
            value = (f.get("header_value") or "").lower()
            vuln_software = ("apache/2.2", "nginx/1.14", "php/5", "iis/6", "openssh_7.")
            if any(v in value for v in vuln_software):
                factors.append({"kind": "context_rule",
                                "rule": "vuln_server_banner",
                                "matched_substring": next(v for v in vuln_software if v in value),
                                "weight": +0.6})
                return "INTERESTING", 0.85, f"vulnerable server software disclosed: {value}"

        # Common test files that 404 → demote to FALSE_ALARM
        if cls == "INTERESTING":
            title_low = (f.get("title") or "").lower()
            common_decoys = ("phpinfo", "favicon", "robots.txt", "crossdomain.xml",
                             "server-status")
            if any(d in title_low for d in common_decoys):
                if f.get("status_code") == 404:
                    factors.append({"kind": "context_rule",
                                    "rule": "decoy_404_demotion",
                                    "weight": -0.8})
                    return "FALSE_ALARM", 0.9, "common decoy file returns 404"

        return cls, conf, reason

    # ---------- output ----------
    @staticmethod
    def _stamp(f: Dict[str, Any], cls: str, conf: float, reason: str,
               factors: List[Dict[str, Any]]) -> Dict[str, Any]:
        f["classification"] = cls
        f["classification_confidence"] = round(conf, 2)
        f["classification_reason"] = reason

        # Structured explanation — what clients/auditors actually need.
        # See README "The classifier" section for the schema contract.
        f["classification_explanation"] = {
            "final_class":     cls,
            "confidence":      round(conf, 2),
            "primary_reason":  reason,
            "factors":         factors,
            "context_chains":  [c.get("name") or c.get("type")
                                 for c in f.get("attack_chains", []) or []],
            "human_explanation": _humanize(cls, reason, factors,
                                            f.get("attack_chains") or []),
        }

        meta = {
            "FALSE_ALARM": {"emoji": "🟢", "color": "green",
                            "action": "no action required",  "priority": 0},
            "COMMON":      {"emoji": "🟡", "color": "yellow",
                            "action": "review and assess",   "priority": 1},
            "INTERESTING": {"emoji": "🔴", "color": "red",
                            "action": "investigate immediately", "priority": 2},
        }
        f["classification_meta"] = meta.get(cls, {})
        f["priority"] = meta.get(cls, {}).get("priority", 0)
        return f


def _humanize(cls: str, reason: str, factors: List[Dict[str, Any]],
              chains: List[Dict[str, Any]]) -> str:
    """Build a one-paragraph human-readable explanation.

    The string is composable from the factors so reports / auditors get
    something better than "Type in INTERESTING_TYPES + severity >= 7.0".
    """
    parts: List[str] = []
    parts.append(f"Classified as {cls} ({reason}).")
    # Surface the highest-weight contributing factor
    if factors:
        ordered = sorted(factors, key=lambda x: abs(x.get("weight", 0)),
                         reverse=True)
        top = ordered[0]
        if top["kind"] == "type_table":
            parts.append(
                f"Primary signal: finding type '{top['value']}' is in "
                f"the {top['table']} table.")
        elif top["kind"] == "module_hint":
            parts.append(
                f"Primary signal: the producing module asserted "
                f"`{top['field']}` on the finding.")
        elif top["kind"] == "signature_pack":
            entry_id = (top.get("matched_entry") or {}).get("id")
            parts.append(
                f"Primary signal: matched the `{top['pack']}` signature pack"
                + (f" (entry `{entry_id}`)" if entry_id else "") + ".")
        elif top["kind"] == "severity_score":
            parts.append(
                f"Primary signal: numeric severity score "
                f"{top['score']:.1f}/10.")
        elif top["kind"] == "context_rule":
            parts.append(
                f"Primary signal: cross-finding context rule "
                f"`{top['rule']}` fired.")
    if chains:
        names = ", ".join(str(c.get("name") or c.get("type") or "chain")
                          for c in chains)
        parts.append(f"Participates in attack chain(s): {names}.")
    return " ".join(parts)


# Re-open FindingClassifier to attach the summary method that the
# scanner engine + tests rely on. Keeping it as a module-level extension
# avoids reshuffling the whole class for an explainability addition.
def _summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    buckets = {"FALSE_ALARM": [], "COMMON": [], "INTERESTING": []}
    for f in findings:
        buckets.setdefault(f.get("classification", "COMMON"), []).append(f)
    return {
        "total": len(findings),
        "false_alarms": len(buckets["FALSE_ALARM"]),
        "common":       len(buckets["COMMON"]),
        "interesting":  len(buckets["INTERESTING"]),
        "top_interesting": sorted(
            buckets["INTERESTING"],
            key=lambda x: x.get("classification_confidence", 0),
            reverse=True,
        )[:10],
    }


FindingClassifier.summarize = staticmethod(_summarize)
