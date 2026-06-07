"""Module ↔ external-tool coverage mapping.

The scanner has three classes of modules:

  * **Pure-Python modules** (header_analyzer, surface_map, etc.) — always
    run; no external tool needed.
  * **External-tool modules with a fallback** (gobuster, ffuf — Python
    HEAD-probe fallback exists for path discovery).
  * **External-tool modules with NO fallback** (nuclei, nikto, hydra,
    sqlmap) — when the tool is missing the module skips itself entirely.

Operators have repeatedly been bitten by the second case: they run
``--mode full`` thinking they're getting comprehensive coverage and
silently get a 50-path Python probe in place of a 100k-path gobuster
sweep. The mapping below makes that explicit, the scanner prints a
warning banner at start, and the scan summary lists exactly what ran
under what coverage tier.

Coverage tiers (per module, per scan):

  * ``full``       — external tool was on PATH and executed
  * ``fallback``   — tool missing but Python fallback ran (degraded)
  * ``skipped``    — tool missing AND no fallback exists
  * ``native``     — Python-only module, no external dependency
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ModuleDep:
    """How a module relates to its external CLI tool and other modules.

    `requires_modules` lists upstream modules whose output this module
    *needs* — when those modules are missing from the scan plan or have
    crashed at runtime, the engine skips this module with a clear note
    instead of running it on empty input. This is the "explicit
    dependency graph" replacement for the implicit phase ordering.
    """

    module:           str
    requires_tool:    Optional[str] = None    # None = pure-Python module
    has_fallback:     bool = False            # True only when fallback path is real
    fallback_note:    str = ""                # what the fallback actually does
    requires_modules: tuple = ()              # hard module deps (empty = independent)

    @property
    def is_native(self) -> bool:
        return self.requires_tool is None


# ---------------------------------------------------------------------------
# The catalogue. Adding a new module = adding a row here. Anything not
# in this table is treated as native (warns instead of crashing — easier
# than failing-closed on a forgotten entry).
# ---------------------------------------------------------------------------
MODULE_DEPS: Dict[str, ModuleDep] = {
    # Pure-Python passive recon
    "headers":     ModuleDep("headers"),
    "fingerprint": ModuleDep("fingerprint"),
    "ssl":         ModuleDep("ssl"),
    "endpoints":   ModuleDep("endpoints"),
    "dns":         ModuleDep("dns"),
    "whois":       ModuleDep("whois"),
    "surface":     ModuleDep("surface"),
    "js":          ModuleDep("js"),
    "js_vulns":    ModuleDep("js_vulns"),
    "dorks":       ModuleDep("dorks"),
    "cors":        ModuleDep("cors"),
    "symfony":     ModuleDep("symfony"),
    # default_creds is pure-Python (uses `requests`); no external tool
    "default_creds": ModuleDep("default_creds"),

    # External-tool modules — these are the ones that matter
    "nikto":    ModuleDep("nikto",    "nikto",
                          has_fallback=False),
    "nuclei":   ModuleDep("nuclei",   "nuclei",
                          has_fallback=False),
    # sqlmap is fed by injectable URLs from endpoint discovery — without
    # `endpoints` it can still run, but the target list is degraded.
    "sqlmap":   ModuleDep("sqlmap",   "sqlmap",
                          has_fallback=False,
                          requires_modules=("endpoints",)),
    "hydra":    ModuleDep("hydra",    "hydra",
                          has_fallback=False),
    "gobuster": ModuleDep("gobuster", "gobuster",
                          has_fallback=True,
                          fallback_note="50-path Python HEAD probe "
                                         "(vs full wordlist sweep)"),
    "ffuf":     ModuleDep("ffuf",     "ffuf",
                          has_fallback=True,
                          fallback_note="endpoint_crawler covers some of the "
                                         "same ground at much lower depth"),
    "wfuzz":    ModuleDep("wfuzz",    "wfuzz",
                          has_fallback=False),
}


# ---------------------------------------------------------------------------
@dataclass
class ModuleCoverageEntry:
    module:  str
    tier:    str                          # full | fallback | skipped | native
    tool:    Optional[str] = None
    tool_present: bool = True
    note:    str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module":       self.module,
            "tier":         self.tier,
            "tool":         self.tool,
            "tool_present": self.tool_present,
            "note":         self.note,
        }


@dataclass
class CoverageReport:
    """The full per-scan coverage snapshot."""
    entries: List[ModuleCoverageEntry] = field(default_factory=list)

    # ---- aggregations ----
    def by_tier(self) -> Dict[str, List[ModuleCoverageEntry]]:
        out: Dict[str, List[ModuleCoverageEntry]] = {
            "full": [], "fallback": [], "skipped": [], "native": []}
        for e in self.entries:
            out.setdefault(e.tier, []).append(e)
        return out

    def degraded_modules(self) -> List[ModuleCoverageEntry]:
        return [e for e in self.entries if e.tier in ("fallback", "skipped")]

    def to_dict(self) -> Dict[str, Any]:
        buckets = self.by_tier()
        return {
            "entries": [e.to_dict() for e in self.entries],
            "summary": {tier: len(items) for tier, items in buckets.items()},
            "degraded_count": len(self.degraded_modules()),
        }


def build_coverage_report(modules: List[str],
                          tool_status: Optional[Dict[str, Dict[str, Any]]] = None
                          ) -> CoverageReport:
    """Build a coverage snapshot for a given module list.

    ``tool_status`` is the dict from ``ToolPathValidator.check_all_tools()``.
    Pass it once at scan start so we don't re-shell out per module.
    """
    if tool_status is None:
        from config.tool_paths import ToolPathValidator
        tool_status = ToolPathValidator().check_all_tools(console=None)

    report = CoverageReport()
    for m in modules:
        dep = MODULE_DEPS.get(m)
        if dep is None or dep.is_native:
            report.entries.append(ModuleCoverageEntry(
                module=m, tier="native"))
            continue
        present = bool((tool_status.get(dep.requires_tool) or {}).get("available"))
        if present:
            report.entries.append(ModuleCoverageEntry(
                module=m, tier="full",
                tool=dep.requires_tool, tool_present=True))
        elif dep.has_fallback:
            report.entries.append(ModuleCoverageEntry(
                module=m, tier="fallback",
                tool=dep.requires_tool, tool_present=False,
                note=dep.fallback_note))
        else:
            report.entries.append(ModuleCoverageEntry(
                module=m, tier="skipped",
                tool=dep.requires_tool, tool_present=False,
                note=f"requires `{dep.requires_tool}` — install via "
                      f"`hunterpy --install-tools` or expect zero "
                      f"coverage from this module"))
    return report


# ---------------------------------------------------------------------------
def render_banner(report: CoverageReport) -> List[str]:
    """One-line summary + table rows for the start-of-scan banner."""
    lines: List[str] = []
    summary = {tier: len(items) for tier, items in report.by_tier().items()}
    lines.append(
        f"Module coverage: {summary.get('full', 0)} full, "
        f"{summary.get('fallback', 0)} fallback, "
        f"{summary.get('skipped', 0)} skipped, "
        f"{summary.get('native', 0)} native")
    for e in report.entries:
        glyph = {"full": "✓", "fallback": "⚠", "skipped": "✗",
                 "native": "·"}.get(e.tier, "?")
        line = f"  {glyph} {e.module:<12s} {e.tier:<10s}"
        if e.tool:
            line += f" tool={e.tool}{'(missing)' if not e.tool_present else ''}"
        if e.note:
            line += f"  — {e.note}"
        lines.append(line)
    return lines


# ---------------------------------------------------------------------------
def unmet_module_requirements(module: str,
                               available_modules: List[str],
                               completed_modules: Optional[List[str]] = None
                               ) -> List[str]:
    """Return any ``requires_modules`` for `module` that are NOT in the
    available/completed set. Used by the engine to skip a module whose
    upstream prerequisites failed or weren't selected."""
    dep = MODULE_DEPS.get(module)
    if dep is None or not dep.requires_modules:
        return []
    universe = set(available_modules)
    if completed_modules is not None:
        # If a completion list was given, only count modules that
        # actually completed successfully.
        universe &= set(completed_modules)
    return [m for m in dep.requires_modules if m not in universe]


class StrictModeError(Exception):
    """Raised when --mode strict can't be satisfied — required tool missing."""


def enforce_strict_mode(report: CoverageReport) -> None:
    """Fail-fast for `--mode strict`. Skipped or fallback = error."""
    degraded = report.degraded_modules()
    if degraded:
        details = "; ".join(
            f"{e.module} ({e.tier}"
            + (f", needs `{e.tool}`" if e.tool else "")
            + ")"
            for e in degraded)
        raise StrictModeError(
            f"--mode strict requires every selected module to run at "
            f"`full` coverage. Degraded modules: {details}. "
            f"Run `hunterpy --install-tools` or pick a different mode.")
