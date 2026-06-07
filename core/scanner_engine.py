"""Main orchestration engine — runs the 5-phase scan pipeline."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.progress_tracker import ProgressTracker
from core.scan_persistence import ScanPersistence
from classifiers.context_graph import ContextGraph
from classifiers.dedup_engine import DedupEngine
from classifiers.finding_classifier import FindingClassifier
from config.settings import Settings
from core.report_engine import ReportEngine
from core.session_manager import SessionManager
from modules.intelligence.baseline_analyzer import BehaviorAnalyzer
from utils.database import Database
from utils.logger import ScanLogger

# module imports
from modules.custom.cors_tester import CORSTester
from modules.custom.dns_enum import DNSEnum
from modules.custom.endpoint_crawler import EndpointCrawler
from modules.custom.header_analyzer import HeaderAnalyzer
from modules.custom.js_analyzer import JSAnalyzer
from modules.custom.ssl_analyzer import SSLAnalyzer
from modules.custom.surface_map import SurfaceMap
from modules.custom.symfony_detector import SymfonyDetector
from modules.custom.tech_fingerprint import TechFingerprint
from modules.custom.whois_lookup import WhoisLookup
from modules.external.nuclei_client import NucleiModule
from modules.external.osv_client import JSPackageVulnScan
from modules.osint.dork_module import DorkModule
from modules.web_scanner.nikto_module import NiktoModule
from modules.web_scanner.gobuster_module import GobusterModule
from modules.web_scanner.ffuf_module import FFUFModule
from modules.web_scanner.wfuzz_module import WFuzzModule
from modules.injection.sqlmap_module import SQLMapModule
from modules.auth_testing.hydra_module import HydraModule
from modules.auth_testing.default_cred_check import DefaultCredCheckModule


def _DefaultCredCheckLazy(settings):
    # Wrapper kept for symmetry with MODULE_MAP (every value is callable
    # with `(settings,)`). Lets us drop the module in without re-shaping
    # the engine's instantiation code.
    return DefaultCredCheckModule(settings)



try:
    from rich.console import Console
    from rich.panel import Panel
    _console = Console()
    _RICH = True
except ImportError:
    _console = None
    _RICH = False


def _print(msg: str, style: Optional[str] = None) -> None:
    if _RICH and _console is not None:
        _console.print(msg, style=style or "")
    else:
        # crude tag stripper for non-rich envs
        import re
        print(re.sub(r"\[/?[^\]]+\]", "", msg))


class ScannerEngine:
    """Orchestrates the 5-phase scan pipeline."""

    EXECUTION_PIPELINE = {
        # Phase 1 is strictly passive — safe for any target the user owns
        # or has authorization on. The passive scan mode runs only these.
        # `dorks` is in phase 1 because the default (preview) mode does
        # zero network I/O — it only renders Google URLs for the analyst.
        "phase1_recon":        ["fingerprint", "headers", "ssl", "endpoints",
                                 "dns", "whois", "surface", "js", "js_vulns",
                                 "dorks", "symfony"],
        # Phase 2: still loud-but-useful tools (gated by mode + tool presence)
        "phase2_scanning":     ["nuclei", "nikto", "gobuster", "ffuf", "wfuzz"],
        "phase3_exploitation": ["sqlmap", "cors"],
        "phase4_auth":         ["default_creds", "hydra"],
        # Hash cracking is NOT in any default pipeline anymore — it's a
        # separate operation (see `hunterpy crack` workflow).
        "phase5_hashes":       [],
    }

    MODULE_MAP = {
        # passive recon
        "headers":     HeaderAnalyzer,
        "fingerprint": TechFingerprint,
        "ssl":         SSLAnalyzer,
        "endpoints":   EndpointCrawler,
        "dns":         DNSEnum,
        "whois":       WhoisLookup,
        "surface":     SurfaceMap,
        "js":          JSAnalyzer,
        "js_vulns":    JSPackageVulnScan,    # OSV.dev lookup, opt-in via mode
        "dorks":       DorkModule,           # preview-only by default
        # Symfony exposure intel pack (built from SECREP-* reports —
        # see signatures/intel/symfony_exposure.json + docs/threat-intel/)
        "symfony":     SymfonyDetector,
        # active
        "nuclei":      NucleiModule,
        "nikto":       NiktoModule,
        "gobuster":    GobusterModule,
        "ffuf":        FFUFModule,
        "wfuzz":       WFuzzModule,
        "sqlmap":      SQLMapModule,
        "cors":        CORSTester,
        "hydra":       HydraModule,
        # default_creds is the safer, always-on auth audit. Hydra remains
        # opt-in via --enable-bruteforce. See docs/AUTH-TESTING.md.
        "default_creds": _DefaultCredCheckLazy,
    }

    def __init__(self, settings: Settings):
        self.settings = settings
        self.db = Database(settings.db_path)
        self.session = SessionManager(settings, db=self.db)
        self.logger = ScanLogger(settings.output_dir)
        self.classifier = FindingClassifier()
        self.dedup = DedupEngine()
        self.context_graph = ContextGraph()
        self.behavior = BehaviorAnalyzer(settings)
        self.reporter = ReportEngine(settings)
        self.all_findings: List[Dict[str, Any]] = []
        self.detected_chains: List[Dict[str, Any]] = []
        self.baseline_snapshot: Dict[str, Any] = {}
        # cross-module artifacts captured for the markdown report
        self.module_artifacts: Dict[str, Dict[str, Any]] = {}
        # coverage report — populated at scan start, written into the
        # markdown frontmatter + printed in the end-of-scan summary
        self.coverage_report = None
        # Module-dependency tracking: which modules ran AND produced
        # non-skip output. Consulted by phase 3 onward to decide whether
        # to skip downstream modules whose prerequisites failed.
        self.progress = ProgressTracker(total_modules=len(settings.modules))
        # Persistence wrapper — engine no longer touches `db.save_checkpoint`
        # directly, so checkpoint failures stop leaking into _safe_run.
        self.persistence = ScanPersistence(db=self.db, logger=self.logger)

    # ---------- main entry ----------
    def run(self) -> Dict[str, Any]:
        _print(f"\n[bold green][+] Starting scan against: {self.settings.target}[/]")
        _print(f"[yellow][*] Mode: {self.settings.mode.upper()} — modules: "
               f"{', '.join(self.settings.modules)}[/]\n")

        # ----- module-coverage warning banner -----
        # Run BEFORE session.begin() so a strict-mode failure aborts
        # cleanly without a half-created scan row.
        from core.module_coverage import (
            build_coverage_report, render_banner, enforce_strict_mode,
            StrictModeError,
        )
        from config.tool_paths import ToolPathValidator
        tool_status = ToolPathValidator().check_all_tools(console=None)
        self.coverage_report = build_coverage_report(
            self.settings.modules, tool_status=tool_status)
        for line in render_banner(self.coverage_report):
            # Yellow for the headline, default for rows — keeps the
            # block scannable. Per-row glyphs already convey severity.
            _print(line, style="yellow" if line.startswith("Module") else None)
        if getattr(self.settings, "mode", "") == "strict":
            try:
                enforce_strict_mode(self.coverage_report)
            except StrictModeError as e:
                _print(f"\n[bold red][!] {e}[/]")
                return {"error": str(e), "status": "aborted"}

        self.session.begin()
        start = time.time()
        try:
            # Profile baseline behavior FIRST so later modules can use it
            _print("\n[bold cyan]═══ PHASE 0: BASELINE PROFILING ═══[/]")
            try:
                bl = self.behavior.establish()
                self.baseline_snapshot = bl.to_dict()
                _print(f"[green][+] Baseline established: "
                       f"mean={bl.length_mean:.0f}B  "
                       f"server={bl.server_header or 'unknown'}  "
                       f"404-sizes={bl.common_404_bodies}[/]")
            except Exception as e:
                self.logger.log_error(f"baseline failed: {e}")
                _print(f"[yellow][~] baseline skipped: {e}[/]")

            recon = self._phase_recon()
            scan  = self._phase_scanning(recon)
            xploit = self._phase_exploitation(recon, scan)
            auth   = self._phase_auth(recon)
            hashes = self._phase_hashes()

            self.all_findings = (
                recon.get("findings", []) + scan + xploit + auth + hashes
            )
            self.all_findings = self.dedup.deduplicate(self.all_findings)
            self.all_findings = self.classifier.classify_all(self.all_findings)

            # Context graph: detect cross-module attack chains
            self.context_graph.add_findings(self.all_findings)
            self.detected_chains = self.context_graph.detect_chains(
                self.all_findings)
            if self.detected_chains:
                _print(f"\n[bold red][!] {len(self.detected_chains)} attack "
                       f"chain(s) detected by context graph[/]")
                # Classify chains as well so they appear in reports
                self.detected_chains = self.classifier.classify_all(
                    self.detected_chains)
                self.all_findings.extend(self.detected_chains)

            # Phase 6 — verification. OFF unless --verify + signed auth file.
            # Safe by design: read-only probes by default, per-finding y/n
            # prompt, full evidence bundle on disk. See docs/VERIFICATION.md.
            if getattr(self.settings, "verify_enabled", False):
                self._phase_verification()
        except KeyboardInterrupt:
            _print("\n[bold red][!] Scan interrupted by user[/]")
        except Exception as e:
            _print(f"\n[bold red][!] Fatal error: {e}[/]")
            self.logger.log_error(str(e))

        elapsed = time.time() - start
        self.session.metadata["duration"] = f"{int(elapsed // 60)}m {int(elapsed % 60)}s"
        if self.coverage_report is not None:
            self.session.metadata["coverage"] = self.coverage_report.to_dict()
        self.session.save_findings(self.all_findings)
        status = "completed" if self.all_findings is not None else "failed"
        self.session.finish(status)

        self._summary()
        self.reporter.generate_all_reports(
            self.all_findings, self.session.metadata,
            artifacts=self.module_artifacts,
            chains=self.detected_chains,
            baseline=self.baseline_snapshot,
        )
        # Big visible "next step" banner per the AI-workflow brief
        _print("")
        _print("[bold green]══════════════════════════════════════════════════════════════[/]")
        _print("[bold green]║   NEXT STEP — PASTE THE MARKDOWN REPORT INTO AN AI         ║[/]")
        _print("[bold green]║   ASSISTANT (ChatGPT / Claude / Gemini) FOR GUIDANCE       ║[/]")
        _print("[bold green]║   ON WHICH FINDINGS TO INVESTIGATE FIRST.                  ║[/]")
        _print("[bold green]══════════════════════════════════════════════════════════════[/]")
        return self.session.metadata

    # ---------- phases ----------
    def _phase_recon(self) -> Dict[str, Any]:
        _print("\n[bold cyan]═══ PHASE 1: RECONNAISSANCE ═══[/]")
        names = [m for m in self.EXECUTION_PIPELINE["phase1_recon"]
                 if m in self.settings.modules]
        recon: Dict[str, Any] = {"findings": [], "technologies": [],
                                  "endpoints": [], "headers": {}}
        if not names:
            return recon

        # js_vulns depends on the js module's output → run sequentially after
        # the others.
        deps_last = [m for m in names if m == "js_vulns"]
        parallel  = [m for m in names if m not in deps_last]

        with ThreadPoolExecutor(max_workers=min(4, max(1, len(parallel)))) as pool:
            futures = {}
            for n in parallel:
                mod = self.MODULE_MAP[n](self.settings)
                if hasattr(mod, "set_context"):
                    mod.set_context(self.module_artifacts)
                futures[pool.submit(self._safe_run, n, mod)] = n
            for fut in as_completed(futures):
                res = fut.result()
                if not res:
                    continue
                recon["findings"].extend(res.get("findings", []))
                recon["technologies"].extend(res.get("technologies", []))
                recon["endpoints"].extend(res.get("endpoints", []))
                if "headers" in res:
                    recon["headers"].update(res["headers"])

        # dependent modules
        for n in deps_last:
            mod = self.MODULE_MAP[n](self.settings)
            if hasattr(mod, "set_context"):
                mod.set_context(self.module_artifacts)
            res = self._safe_run(n, mod)
            if res:
                recon["findings"].extend(res.get("findings", []))

        _print(f"[green][+] Recon: {len(recon['findings'])} findings, "
               f"{len(recon['technologies'])} techs, "
               f"{len(recon['endpoints'])} endpoints[/]")
        return recon

    def _phase_scanning(self, recon: Dict[str, Any]) -> List[Dict[str, Any]]:
        _print("\n[bold yellow]═══ PHASE 2: ACTIVE SCANNING ═══[/]")
        names = [m for m in self.EXECUTION_PIPELINE["phase2_scanning"]
                 if m in self.settings.modules]
        findings: List[Dict[str, Any]] = []
        for n in names:
            mod = self.MODULE_MAP[n](self.settings)
            if hasattr(mod, "set_context"):
                mod.set_context(recon)
            res = self._safe_run(n, mod)
            if res:
                findings.extend(res.get("findings", []))
        return findings

    def _phase_exploitation(self, recon: Dict[str, Any],
                            scan_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        from core.module_coverage import unmet_module_requirements

        _print("\n[bold red]═══ PHASE 3: TARGETED TESTING ═══[/]")
        names = [m for m in self.EXECUTION_PIPELINE["phase3_exploitation"]
                 if m in self.settings.modules]
        findings: List[Dict[str, Any]] = []
        for n in names:
            # Enforce module dependencies: if a required upstream module
            # was either not in the plan OR completed with `skipped`,
            # don't run a downstream module that needs its output.
            unmet = unmet_module_requirements(
                n, available_modules=list(self.settings.modules),
                completed_modules=self.progress.completed_modules)
            if unmet:
                _print(f"[yellow][~] {n}: skipped — required upstream "
                       f"module(s) did not run: {unmet}[/]")
                continue
            mod = self.MODULE_MAP[n](self.settings)
            if hasattr(mod, "set_context"):
                mod.set_context(recon)
            if n == "sqlmap":
                injectable = self._injectable_urls(scan_findings + recon.get("findings", []))
                if hasattr(mod, "set_targets"):
                    mod.set_targets(injectable)
            res = self._safe_run(n, mod)
            if res:
                findings.extend(res.get("findings", []))
        return findings

    def _phase_auth(self, recon: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        ran_anything = False

        # default_creds: ALWAYS runs (if enabled in module list).
        # Single-shot common-pair audit; ~20 requests max per endpoint.
        if "default_creds" in self.settings.modules:
            _print("\n[bold magenta]═══ PHASE 4a: DEFAULT-CRED AUDIT ═══[/]")
            mod = self.MODULE_MAP["default_creds"](self.settings)
            if hasattr(mod, "set_context"):
                mod.set_context(recon)
            res = self._safe_run("default_creds", mod)
            if res:
                findings.extend(res.get("findings", []))
            ran_anything = True

        # hydra: legacy brute-force, gated behind --enable-bruteforce
        # AND --auth-url/--password-list. Most engagements should NOT
        # be running this.
        if "hydra" in self.settings.modules:
            if not getattr(self.settings, "enable_bruteforce", False):
                _print("[yellow][*] Skipping Hydra phase — pass "
                       "--enable-bruteforce to actually run web brute-force "
                       "(noisy, slow, often out-of-SOW). default_creds "
                       "already covered the documented default pairs.[/]")
            elif not self.settings.auth_url and not self.settings.password_list:
                _print("[yellow][*] Skipping Hydra phase — no --auth-url "
                       "or --password-list[/]")
            else:
                _print("\n[bold magenta]═══ PHASE 4b: BRUTE-FORCE (HYDRA) ═══[/]")
                mod = HydraModule(self.settings)
                res = self._safe_run("hydra", mod)
                if res:
                    findings.extend(res.get("findings", []))
                ran_anything = True

        if not ran_anything:
            _print("[yellow][*] Skipping auth phase — no auth modules in "
                   "the module list[/]")
        return findings

    def _phase_hashes(self) -> List[Dict[str, Any]]:
        names = [m for m in self.EXECUTION_PIPELINE["phase5_hashes"]
                 if m in self.settings.modules]
        if not names:
            return []
        hashes = self._extracted_hashes()
        if not hashes:
            _print("[yellow][*] No hashes discovered — skipping hash phase[/]")
            return []
        _print("\n[bold blue]═══ PHASE 5: HASH ANALYSIS ═══[/]")
        findings: List[Dict[str, Any]] = []
        for n in names:
            mod = self.MODULE_MAP[n](self.settings)
            if hasattr(mod, "set_hashes"):
                mod.set_hashes(hashes)
            res = self._safe_run(n, mod)
            if res:
                findings.extend(res.get("findings", []))
        return findings

    # ---------- helpers ----------
    def _safe_run(self, name: str, module) -> Dict[str, Any]:
        _print(f"[cyan][*] Running module: {name}[/]")
        self.progress.mark_started(name)
        try:
            res = module.run()
            self.session.record_module(name)
            count = len(res.get("findings", [])) if res else 0
            skip = res.get("skipped") if res else None
            if skip:
                _print(f"[yellow][~] {name}: skipped — {skip}[/]")
            else:
                _print(f"[green][+] {name}: {count} findings[/]")
                # Mark as completed only when not skipped — downstream
                # modules' requires_modules check looks at this set.
                self.progress.mark_completed(name)
            # Persistence is a separate concern from orchestration —
            # checkpoint failure logs but never aborts the scan.
            self.persistence.save_checkpoint(
                self.session.scan_id, name, "completed", res or {})
            if res:
                self.module_artifacts[name] = res
            return res or {}
        except Exception as e:
            _print(f"[red][!] {name} failed: {e}[/]")
            self.logger.log_error(f"{name} failed: {e}")
            self.progress.mark_failed(name, f"{type(e).__name__}: {e}")
            return {}

    @staticmethod
    def _injectable_urls(findings: List[Dict[str, Any]]) -> List[str]:
        out = set()
        for f in findings:
            url = f.get("url") or ""
            if "?" in url or f.get("has_params"):
                out.add(url)
        return sorted(out)

    def _extracted_hashes(self) -> List[str]:
        out = []
        for f in self.all_findings:
            if f.get("type") == "hash_discovered":
                out.append(f.get("raw"))
            if f.get("type") == "hash_found":
                out.extend(f.get("hashes", []))
        return [h for h in out if h]

    # ------------------------------------------------------------------
    def _phase_verification(self) -> None:
        """Phase 6: post-classification safe verification.

        Runs only when ``--verify`` is set. The verifier itself enforces
        authorization, scope, safety level, and rate limiting — we just
        wire the pieces together and pass the finding list in.
        """
        from modules.exploit.authorization import (
            AuthorizationError, ensure_authorized, load_authorization,
        )
        from modules.exploit.collaborator import make_collaborator
        from modules.exploit.verifier import Verifier, VerifierConfig

        _print("\n[bold magenta]═══ PHASE 6: SAFE VERIFICATION ═══[/]")

        auth_path = getattr(self.settings, "verify_auth_file", None)
        if not auth_path:
            _print("[red][!] --verify was set but --verify-auth-file is "
                   "missing — refusing to run verification[/]")
            return
        try:
            auth = load_authorization(auth_path)
            ensure_authorized(auth, hostname=self.settings.target,
                               requested_safety="read_only")
        except AuthorizationError as e:
            _print(f"[red][!] verification refused: {e}[/]")
            return

        _print(f"[green][+] authorization OK — engagement={auth.engagement!r} "
               f"operator={auth.operator!r} expires={auth.expires_at}[/]")

        # Build collaborator (external if url given, local listener otherwise)
        collab = make_collaborator(
            getattr(self.settings, "verify_collaborator_url", None)
        )
        # Start the local listener if applicable
        if hasattr(collab, "start"):
            try:
                collab.start()
            except Exception as e:
                self.logger.log_error(f"local collaborator failed to start: {e}")
                collab = None

        cfg = VerifierConfig(
            output_dir=self.settings.output_dir,
            rate_limit_per_sec=getattr(self.settings,
                                        "verify_rate_limit_per_sec", 0.5),
            non_interactive=getattr(self.settings,
                                     "verify_non_interactive", False),
            allow_destructive=getattr(self.settings,
                                       "verify_allow_destructive", False),
            only_types=list(getattr(self.settings, "verify_only_types", []) or []),
            max_findings=getattr(self.settings, "verify_max_findings", 50),
            write_poc=getattr(self.settings, "write_poc", False),
        )
        verifier = Verifier(
            config=cfg, authorization=auth, collaborator=collab,
            settings=self.settings,
        )
        try:
            results = verifier.verify_findings(self.all_findings)
        finally:
            if hasattr(collab, "stop"):
                try:
                    collab.stop()
                except Exception:
                    pass

        # Summary
        confirmed = sum(1 for r in results
                        if (getattr(r.status, "value", r.status) == "confirmed"))
        inconclusive = sum(1 for r in results
                           if (getattr(r.status, "value", r.status) == "inconclusive"))
        skipped = sum(1 for r in results
                      if (getattr(r.status, "value", r.status) == "skipped"))
        _print(f"[bold]Verification: {confirmed} confirmed, "
               f"{inconclusive} inconclusive, {skipped} skipped, "
               f"{len(results)} total[/]")
        _print(f"[green]Evidence bundles: {self.settings.output_dir}/verification/[/]")

    # ------------------------------------------------------------------
    def _summary(self) -> None:
        s = self.classifier.summarize(self.all_findings)
        _print("\n[bold]═══ SCAN RESULTS SUMMARY ═══[/]")
        _print(f"  🔴 INTERESTING: {s['interesting']}   (investigate!)")
        _print(f"  🟡 COMMON:      {s['common']}   (review)")
        _print(f"  🟢 FALSE ALARM: {s['false_alarms']}   (skip)")
        _print(f"\n[bold]Total findings: {s['total']}[/]")

        # Re-print module coverage at the end so the operator doesn't
        # have to scroll back up. Degraded scans without this reminder
        # are exactly how "I thought I ran nuclei" incidents happen.
        if self.coverage_report is not None:
            degraded = self.coverage_report.degraded_modules()
            if degraded:
                _print("\n[bold yellow]Coverage warnings — the following "
                       "modules ran at reduced coverage:[/]")
                for e in degraded:
                    glyph = "⚠" if e.tier == "fallback" else "✗"
                    _print(f"  {glyph} {e.module:<12s} "
                           f"{e.tier:<10s} {e.note}")
                _print("[dim]Run `hunterpy --install-tools` to plan an "
                       "install of the missing tools.[/]")

        _print(f"[green]Reports saved to: {self.settings.output_dir}[/]\n")
