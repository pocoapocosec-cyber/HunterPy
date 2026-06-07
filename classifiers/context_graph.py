"""Attack-surface graph for cross-finding impact analysis.

Not deep-learning, not 'AI' — just a small graph of:
  asset → exposed_surface → finding
plus a handful of well-known exploitation chains. The goal is to detect
when several individually-COMMON findings combine into something
INTERESTING (e.g. dev subdomain + .git/HEAD + missing auth).

Chains are declarative so they're auditable and easy to extend.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse


# Each chain: (name, severity_upgrade, list of predicates)
# A chain fires when EVERY predicate matches at least one finding in the set.
CHAINS: List[Dict[str, Any]] = [
    {
        "name": "exposed_source_on_dev_subdomain",
        "boost": "INTERESTING",
        "rationale": "Dev subdomain leaking source repo or env config",
        "predicates": [
            {"type": "dev_subdomain"},
            {"any_type": ["git_exposed", "env_exposed", "config_exposed"]},
        ],
    },
    {
        "name": "outdated_software_with_open_admin",
        "boost": "INTERESTING",
        "rationale": "Known-vulnerable software + reachable admin path",
        "predicates": [
            {"type": "cve"},
            {"any_type": ["admin_panel"]},
        ],
    },
    {
        "name": "weak_csp_plus_login_form",
        "boost": "INTERESTING",
        "rationale": "Login form on page that allows unsafe-inline scripts",
        "predicates": [
            {"type": "weak_csp"},
            {"type": "login_form"},
        ],
    },
    {
        "name": "cors_wildcard_with_session_cookie",
        "boost": "INTERESTING",
        "rationale": "Permissive CORS could read session cookies",
        "predicates": [
            {"any_type": ["cors_wildcard", "cors_with_credentials", "cors_reflection"]},
            {"type": "weak_cookie"},
        ],
    },
    {
        "name": "sql_injection_plus_admin",
        "boost": "INTERESTING",
        "rationale": "SQL injection on app exposing admin surface — escalation likely",
        "predicates": [
            {"type": "sql_injection"},
            {"any_type": ["admin_panel", "directory_found"]},
        ],
    },

    # ---- Symfony chains derived from real-world SECREP* incidents ----
    # See signatures/intel/symfony_exposure.json for the source.
    {
        "name": "symfony_full_pwnage",
        "boost": "INTERESTING",
        "rationale": ("Symfony profiler + credential / source leak — the "
                      "exact chain observed in SECREP1 and SECREP2."),
        "predicates": [
            {"any_type": ["symfony_profiler_exposed",
                          "symfony_profiler_phpinfo",
                          "symfony_legacy_profiler"]},
            {"any_type": ["symfony_profiler_lfi",
                          "symfony_legacy_parameters_yml",
                          "symfony_exposed_credentials"]},
        ],
    },
    {
        "name": "symfony_dev_mode_in_prod",
        "boost": "INTERESTING",
        "rationale": ("Symfony app_dev.php / APP_ENV injection reachable "
                      "in production — the profiler can be re-enabled by "
                      "anyone with the URL."),
        "predicates": [
            {"any_type": ["symfony_legacy_dev_front_controller",
                          "symfony_app_env_injection",
                          "symfony_app_debug_injection"]},
            {"any_type": ["symfony_profiler_exposed",
                          "symfony_profiler_phpinfo",
                          "symfony_legacy_profiler"]},
        ],
    },
    {
        "name": "imagemagick_upload_rce_recipe",
        "boost": "INTERESTING",
        "rationale": ("Vulnerable ImageMagick + unrestricted upload + "
                      "EOL PHP — the SECREP1 chain. Each part alone is "
                      "concerning; together they form an RCE recipe."),
        "predicates": [
            {"any_type": ["unrestricted_file_upload"]},
            {"any_type": ["imagemagick_vulnerable_version",
                          "eol_php_with_dangerous_functions"]},
        ],
    },
]


class ContextGraph:
    """Graph of (asset → finding) plus exploitation-chain detection."""

    def __init__(self):
        self.nodes_by_url: Dict[str, List[Dict[str, Any]]] = {}

    # ---------- build ----------
    def add_findings(self, findings: List[Dict[str, Any]]) -> None:
        for f in findings:
            host = self._host(f.get("url") or "")
            self.nodes_by_url.setdefault(host, []).append(f)

    # ---------- analyze ----------
    def detect_chains(self, findings: List[Dict[str, Any]]
                      ) -> List[Dict[str, Any]]:
        """Return a list of new synthetic findings for every chain that fires."""
        out: List[Dict[str, Any]] = []
        for chain in CHAINS:
            matched = self._evaluate_chain(chain, findings)
            if matched:
                out.append({
                    "module": "context_graph",
                    "type":   f"chain_{chain['name']}",
                    "url":    self._pick_url(matched),
                    "severity": "HIGH",
                    "title":  f"Attack chain: {chain['name'].replace('_', ' ')}",
                    "details": chain["rationale"],
                    "evidence": {
                        "chain": chain["name"],
                        "linked_findings": [m.get("title") for m in matched],
                    },
                    "interesting": True,
                    "confirmed": False,
                })
        return out

    def asset_summary(self) -> Dict[str, int]:
        """How many findings per asset (host)."""
        return {host: len(items) for host, items in self.nodes_by_url.items()}

    # ---------- internals ----------
    @staticmethod
    def _evaluate_chain(chain, findings) -> List[Dict[str, Any]]:
        matched: List[Dict[str, Any]] = []
        for pred in chain["predicates"]:
            hit = next((f for f in findings if ContextGraph._matches(pred, f)),
                       None)
            if hit is None:
                return []
            matched.append(hit)
        return matched

    @staticmethod
    def _matches(pred: Dict[str, Any], f: Dict[str, Any]) -> bool:
        ftype = (f.get("type") or "").lower()
        if "type" in pred:
            if pred["type"] == "dev_subdomain":
                url = (f.get("url") or "").lower()
                return any(p + "." in url for p in
                           ("dev", "staging", "test", "qa", "preprod"))
            if pred["type"] == "login_form":
                if ftype == "login_form":
                    return True
                ev = f.get("evidence") or {}
                fields = ev.get("fields") if isinstance(ev, dict) else None
                if fields and any(i.get("type") == "password" for i in fields):
                    return True
                return False
            if ftype == pred["type"].lower():
                return True
        if "any_type" in pred and ftype in {t.lower() for t in pred["any_type"]}:
            return True
        return False

    @staticmethod
    def _host(url: str) -> str:
        try:
            return urlparse(url).netloc or url
        except Exception:
            return url

    @staticmethod
    def _pick_url(matched: List[Dict[str, Any]]) -> str:
        for f in matched:
            if f.get("url"):
                return f["url"]
        return ""
