"""Google-dork builder — pure function, no network.

Reads templates from `signatures/dork_templates.json` and renders them
against a target hostname. Returns ready-to-paste Google search URLs
plus the raw query strings so users / downstream callers can decide
what to do with them.

This is the *safe* core: it never touches Google. The active scraping
client (`google_searcher.py`) builds on top of it when the user
explicitly opts in.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


log = logging.getLogger("hunterpy.dork_builder")


SIG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "signatures",
)


def _load_templates(path: Optional[str] = None) -> Dict[str, Any]:
    path = path or os.path.join(SIG_DIR, "dork_templates.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f).get("templates", {})
    except (OSError, ValueError) as e:
        log.warning("could not load dork templates: %s", e)
        return {}


GOOGLE_SEARCH = "https://www.google.com/search?q="
BING_SEARCH   = "https://www.bing.com/search?q="
DDG_SEARCH    = "https://duckduckgo.com/?q="


@dataclass
class Dork:
    """A single rendered dork."""
    template:    str
    description: str
    severity:    str
    query:       str
    google_url:  str
    bing_url:    str
    ddg_url:     str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DorkSet:
    """All dorks generated for one target."""
    target:   str
    dorks:    List[Dork] = field(default_factory=list)

    def by_template(self) -> Dict[str, List[Dork]]:
        out: Dict[str, List[Dork]] = {}
        for d in self.dorks:
            out.setdefault(d.template, []).append(d)
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "count":  len(self.dorks),
            "dorks":  [d.to_dict() for d in self.dorks],
        }


class DorkBuilder:
    """Renders dork templates against a target. No network calls."""

    def __init__(self, templates_path: Optional[str] = None):
        self.templates = _load_templates(templates_path)

    # ------------------------------------------------------------------
    def list_templates(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": name,
                "description": t.get("description", ""),
                "severity": t.get("severity", "info"),
                "query_count": len(t.get("queries", [])),
            }
            for name, t in self.templates.items()
        ]

    def build(self, target: str,
              only: Optional[List[str]] = None,
              extra_keywords: Optional[str] = None) -> DorkSet:
        """Render every template (or only those in `only`) against `target`.

        Args:
            target: hostname/domain to substitute into `{target}` and `{site}`.
            only:   optional list of template names to include.
            extra_keywords: appended to every rendered query (for refinement).
        """
        target = (target or "").strip().lower()
        if not target:
            return DorkSet(target="")

        chosen = self.templates if not only else {
            n: t for n, t in self.templates.items() if n in only
        }

        out = DorkSet(target=target)
        for name, tmpl in chosen.items():
            for raw in tmpl.get("queries", []):
                query = (raw.replace("{target}", target)
                            .replace("{site}",   target))
                if extra_keywords:
                    query = f"{query} {extra_keywords}".strip()
                out.dorks.append(self._make_dork(
                    name, tmpl.get("description", ""),
                    tmpl.get("severity", "info"),
                    query,
                ))
        return out

    def build_custom(self, target: str, query_pattern: str,
                     severity: str = "info") -> Dork:
        """One-off dork rendering for ad-hoc queries."""
        query = (query_pattern.replace("{target}", target)
                              .replace("{site}",   target))
        return self._make_dork("custom", "custom query", severity, query)

    # ------------------------------------------------------------------
    @staticmethod
    def _make_dork(template: str, description: str, severity: str,
                   query: str) -> Dork:
        enc = urllib.parse.quote_plus(query)
        return Dork(
            template=template,
            description=description,
            severity=severity,
            query=query,
            google_url=f"{GOOGLE_SEARCH}{enc}",
            bing_url=f"{BING_SEARCH}{enc}",
            ddg_url=f"{DDG_SEARCH}{enc}",
        )
