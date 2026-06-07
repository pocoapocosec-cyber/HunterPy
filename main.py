"""HunterPy / Advanced Web Security Scanner — CLI entry point.

Usage:
  python main.py -t https://example.com --confirm-authorized --mode quick
  python main.py -t example.com --confirm-authorized --modules headers ssl cors
  python main.py --list-scans
  python main.py --clear-nvd-cache
"""
from __future__ import annotations

import argparse
import sys

from config.settings import Settings
from config.tool_paths import ToolPathValidator
from core.scanner_engine import ScannerEngine
from core.target_validator import TargetValidator
from utils.database import Database


try:
    from rich.console import Console
    from rich.panel import Panel
    _console = Console()
    _RICH = True
except ImportError:
    _console = None
    _RICH = False


BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║           ADVANCED WEB SECURITY SCANNER — HunterPy           ║
║                  White-hat / Bug-bounty tool                 ║
║                For *authorized* testing only                 ║
╚══════════════════════════════════════════════════════════════╝
"""


def _print(msg, style=None):
    if _RICH and _console:
        _console.print(msg, style=style or "")
    else:
        import re
        print(re.sub(r"\[/?[^\]]+\]", "", msg))


# ----------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hunterpy",
        description="Advanced Web Security Scanner — bug-bounty tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    tg = p.add_argument_group("Target")
    tg.add_argument("-t", "--target", help="Target URL or hostname")
    tg.add_argument("-tL", "--target-list", help="File with one target per line")
    tg.add_argument("--scope", help="Scope file restricting allowed domains")

    sg = p.add_argument_group("Scan Mode")
    sg.add_argument("--mode",
                    choices=("passive", "quick", "standard", "full", "stealth",
                             "strict", "best-effort", "custom"),
                    default="standard",
                    help="Scan intensity (default: standard). Use 'passive' "
                         "for strictly non-intrusive recon → AI-ready report. "
                         "'strict' fails-fast if any required tool is missing. "
                         "'best-effort' explicitly allows Python fallbacks for "
                         "missing tools (and silences the warning banner).")
    sg.add_argument("--modules", nargs="+",
                    choices=("nikto", "sqlmap", "gobuster", "ffuf", "wfuzz",
                             "hydra", "nuclei",
                             "headers", "cors", "ssl", "fingerprint", "endpoints",
                             "dns", "whois", "surface", "js", "js_vulns",
                             "dorks", "symfony", "default_creds"),
                    help="Run only these modules")

    ag = p.add_argument_group("Authentication Testing")
    ag.add_argument("--auth-url", help="Login URL for auth testing")
    ag.add_argument("--username")
    ag.add_argument("--username-list")
    ag.add_argument("--password-list")

    og = p.add_argument_group("Output")
    og.add_argument("-o", "--output", default="./output")
    og.add_argument("--format",
                    choices=("txt", "json", "html", "md", "markdown", "burp", "all"),
                    default="all",
                    help="Report format. 'md' = AI-pasteable Markdown. "
                         "'burp' = Burp Suite issue-import XML (import via "
                         "Project options ▸ Misc ▸ Issue import). "
                         "'all' produces every format including burp.xml.")
    og.add_argument("-v", "--verbose", action="store_true")
    og.add_argument("--no-color", action="store_true")

    safe = p.add_argument_group("Safety & Ethics")
    safe.add_argument("--confirm-authorized", action="store_true",
                      help="REQUIRED: confirm you are authorized to test the target")
    safe.add_argument("--i-am-authorized", action="store_true",
                      help="Skip the interactive hostname-typing confirmation. "
                           "ONLY for CI / automation where consent is "
                           "recorded out-of-band.")
    safe.add_argument("--rate-limit", type=int, default=10,
                      help="Max requests/sec (default 10)")
    safe.add_argument("--delay", type=float, default=0.1)

    cfg = p.add_argument_group("Configuration")
    cfg.add_argument("--threads", type=int, default=10)
    cfg.add_argument("--timeout", type=int, default=30)
    cfg.add_argument("--proxy")
    cfg.add_argument("--user-agent",
                     help="Override the User-Agent string for every request. "
                          "Default identifies HunterPy in target logs "
                          "(`HunterPy/2.0 (+authorized-testing)`) — that's "
                          "deliberate; override only when WAF / cloaking / "
                          "UA-conditional rendering matters.")
    cfg.add_argument("--user-agent-preset", dest="user_agent_preset",
                     help="Use a built-in UA preset by name "
                          "(see --list-user-agents). Examples: chrome-windows, "
                          "firefox-linux, safari-ios, desktop-browsers.")
    cfg.add_argument("--user-agent-pool", dest="user_agent_pool", nargs="+",
                     metavar="UA",
                     help="Explicit list of UA strings to rotate through. "
                          "Pair with --user-agent-strategy.")
    cfg.add_argument("--user-agent-file", dest="user_agent_file",
                     help="Load a UA pool from a file (one per line, "
                          "`#` comments allowed).")
    cfg.add_argument("--user-agent-strategy", dest="user_agent_strategy",
                     choices=("static", "rotate-random", "rotate-sequential"),
                     default="static",
                     help="How to pick a UA per request when the pool has "
                          ">1 entry. Default 'static' uses the first entry.")
    cfg.add_argument("--list-user-agents", action="store_true",
                     help="Print available UA presets and exit.")
    cfg.add_argument("--cookies")
    cfg.add_argument("--headers", nargs="+")
    cfg.add_argument("--sqlmap-level", type=int, choices=range(1, 6),
                     dest="sqlmap_level",
                     help="Override sqlmap --level (1-5). Default depends on "
                          "--mode: passive/quick/stealth=1, standard=2, "
                          "full/strict=3. Higher levels catch more blind / "
                          "second-order / JSON SQLi at the cost of noise + time.")
    cfg.add_argument("--sqlmap-risk", type=int, choices=(1, 2, 3),
                     dest="sqlmap_risk",
                     help="Override sqlmap --risk (1-3). Default depends on "
                          "--mode: passive/quick/standard/stealth=1, "
                          "full/strict=2. risk=3 enables stacked queries + "
                          "heavy time-based payloads; only use on test boxes.")
    cfg.add_argument("--enable-bruteforce", action="store_true",
                     dest="enable_bruteforce",
                     help="Enable the legacy Hydra-based credential "
                          "brute-force module. Off by default — "
                          "default_cred_check (a single-shot common-pair "
                          "audit) is the recommended replacement and is "
                          "always on. Brute-forcing web logins is noisy, "
                          "ineffective on modern apps, and often out of SOW.")

    nvd = p.add_argument_group("NVD CVE feed")
    nvd.add_argument("--no-nvd", action="store_true",
                     help="Disable live NVD lookups")
    nvd.add_argument("--nvd-offline", action="store_true",
                     help="Never contact the network for CVE data")
    nvd.add_argument("--nvd-api-key", help="NVD API key (or set $NVD_API_KEY)")

    dk = p.add_argument_group("Google dorks (OSINT)")
    dk.add_argument("--dork-templates", nargs="+",
                    help="Limit dork generation to these template names "
                         "(see --list-dork-templates)")
    dk.add_argument("--dork-extra", default="",
                    help="Extra keywords appended to every rendered dork")
    dk.add_argument("--dorks-active", action="store_true",
                    help="ACTUALLY scrape Google for each rendered dork. "
                         "Loud, ToS-violating, CAPTCHA-prone. Defaults to off.")
    dk.add_argument("--confirm-dork-scraping", action="store_true",
                    help="Second confirmation required to enable --dorks-active.")
    dk.add_argument("--dork-max-queries", type=int, default=5,
                    help="Cap on distinct dorks to scrape in active mode")
    dk.add_argument("--dork-max-results", type=int, default=10,
                    help="Cap on results per dork in active mode")
    dk.add_argument("--list-dork-templates", action="store_true",
                    help="Print available dork templates and exit")

    vf = p.add_argument_group("Verification (safe exploit confirmation)")
    vf.add_argument("--verify", action="store_true",
                    help="After classification, run safe verification probes "
                         "against INTERESTING/CRITICAL/HIGH findings. Requires "
                         "--verify-auth-file. See docs/VERIFICATION.md.")
    vf.add_argument("--verify-auth-file",
                    help="Path to a signed authorization JSON file produced "
                         "by `--verify-issue-auth`. Required for --verify.")
    vf.add_argument("--verify-non-interactive", action="store_true",
                    help="Skip the per-finding y/n prompt. ONLY for CI runs "
                         "where consent is recorded out-of-band — the "
                         "authorization file's scope/expiry still applies.")
    vf.add_argument("--verify-allow-destructive", action="store_true",
                    help="Permit probes whose safety_level is 'destructive' "
                         "(probes that cannot reliably clean up their changes). "
                         "Default off. The authorization file must ALSO have "
                         "allow_destructive=true.")
    vf.add_argument("--verify-rate-limit", dest="verify_rate_limit_per_sec",
                    type=float, default=0.5,
                    help="Max verification probes per second (default 0.5)")
    vf.add_argument("--verify-only-types", nargs="+", dest="verify_only_types",
                    help="If given, only verify these finding types")
    vf.add_argument("--verify-max-findings", type=int, default=50,
                    help="Hard cap on number of findings verified per scan")
    vf.add_argument("--verify-collaborator-url", dest="verify_collaborator_url",
                    help="External OOB collaborator base URL "
                         "(interactsh-style). If omitted, a local listener "
                         "is started on 127.0.0.1 for probes that need it.")
    vf.add_argument("--write-poc", action="store_true", dest="write_poc",
                    help="After each CONFIRMED verification, write a "
                         "standalone reproducer (poc.sh + poc.py + poc.md) "
                         "into the finding's evidence directory. The "
                         "operator runs them manually; nothing fires "
                         "automatically. See docs/VERIFICATION.md.")

    # `verify-issue-auth` is a side-channel; it short-circuits main() to
    # write a signed authorization file without starting a scan.
    iss = p.add_argument_group("Verification — issue an authorization file")
    iss.add_argument("--verify-issue-auth", metavar="OUTFILE",
                     help="Write a new signed authorization file to OUTFILE "
                          "and exit. Use --verify-engagement / --verify-operator "
                          "/ --verify-hostnames / --verify-valid-days / "
                          "--verify-max-safety / --verify-allow-destructive-auth "
                          "to populate it.")
    iss.add_argument("--verify-engagement",  default="ad-hoc")
    iss.add_argument("--verify-operator",    default="unknown")
    iss.add_argument("--verify-hostnames",   nargs="+",
                     help="Hostnames (or fnmatch globs) the auth covers")
    iss.add_argument("--verify-valid-days",  type=int, default=7)
    iss.add_argument("--verify-max-safety",  default="trivial_write",
                     choices=("read_only", "noisy_read",
                              "trivial_write", "destructive"))
    iss.add_argument("--verify-allow-destructive-auth", action="store_true",
                     help="Permit destructive probes (also requires "
                          "--verify-max-safety=destructive)")
    iss.add_argument("--verify-notes", default="")

    util = p.add_argument_group("Utilities")
    util.add_argument("--list-scans", action="store_true",
                      help="Show previous scans and exit")
    util.add_argument("--clear-nvd-cache", action="store_true",
                      help="Wipe the on-disk NVD cache and exit")
    util.add_argument("--check-tools", action="store_true",
                      help="Print tool availability and exit")
    util.add_argument("--install-tools", action="store_true",
                      help="Plan installation of missing scanner tools and "
                           "exit. By default this is a DRY-RUN — pass "
                           "--install-tools-confirm to actually execute. See "
                           "config/tool_installer.py for the pinned versions.")
    util.add_argument("--install-tools-confirm", action="store_true",
                      help="Required to actually execute the install plan "
                           "from --install-tools. The installer will refuse "
                           "to run sudo steps unless `sudo -v` was run first.")
    util.add_argument("--install-tools-only", nargs="+",
                      help="Restrict --install-tools to a subset of tools")
    util.add_argument("--install-tools-optional", action="store_true",
                      help="Include optional tools (nmap/curl/whatweb) in "
                           "the install plan")
    util.add_argument("--install-tools-lockfile", default="tools.lock.json",
                      help="Path for the install lockfile (default ./tools.lock.json)")
    return p


# ----------------------------------------------------------------
def main(argv=None) -> int:
    _print(BANNER, style="bold cyan")
    args = build_parser().parse_args(argv)

    # utility commands first
    if args.check_tools:
        ToolPathValidator().check_all_tools(console=_console)
        return 0
    if args.list_scans:
        db = Database("hunterpy.db")
        for row in db.list_scans():
            print(f"#{row['id']:<4} {row['status']:<10} {row['scan_mode']:<10} "
                  f"{row['target']:<32} {row['start_time']}")
        return 0
    if args.clear_nvd_cache:
        from modules.custom._nvd_client import NVDClient
        NVDClient(db_path="hunterpy.db").clear_cache()
        print("NVD cache cleared.")
        return 0

    if args.install_tools:
        from config.tool_installer import run_installer
        results, _plat = run_installer(
            only=args.install_tools_only,
            include_optional=args.install_tools_optional,
            dry_run=not args.install_tools_confirm,
            lockfile=args.install_tools_lockfile,
            printer=lambda m: _print(m),
        )
        # Exit zero on a clean dry-run or when every non-skipped plan
        # succeeded. We treat manual-only (Go) plans as not-an-error.
        failures = [r for r in results
                    if not r.success and not r.already_installed
                    and not (r.skipped and r.notes and "manual-only" in r.notes)
                    and not (r.skipped and r.notes and "dry-run" in r.notes)]
        return 0 if not failures else 1

    if args.verify_issue_auth:
        return _issue_auth(args)

    if args.list_dork_templates:
        from modules.osint.dork_builder import DorkBuilder
        for t in DorkBuilder().list_templates():
            print(f"  {t['severity']:<8} {t['name']:<22} "
                  f"({t['query_count']} queries) — {t['description']}")
        return 0

    if args.list_user_agents:
        from config.user_agents import list_presets, PRESETS
        _print("\n[bold]Available User-Agent presets:[/]\n")
        for p in list_presets():
            tag = ""
            if p["category"] == "noisy_impersonation":
                tag = " [bold red](impersonation — read description)[/]"
            elif p["category"] == "tool":
                tag = " [yellow](tool fingerprint)[/]"
            _print(f"  [cyan]{p['name']:<22}[/] {p['count']:>2} UA(s)  "
                   f"— {p['description']}{tag}")
        _print("\nUsage:")
        _print("  --user-agent-preset <name>")
        _print("  --user-agent-pool 'UA1' 'UA2' ...")
        _print("  --user-agent-file path/to/uas.txt")
        _print("  --user-agent-strategy {static,rotate-random,rotate-sequential}")
        return 0

    # Guard active scraping behind both flags
    if args.dorks_active and not args.confirm_dork_scraping:
        _print("[bold red]ERROR:[/] --dorks-active requires --confirm-dork-scraping "
               "(scraping Google violates ToS and triggers CAPTCHAs fast)")
        return 2

    if not args.target:
        _print("[bold red]ERROR:[/] --target is required (or use --list-scans / --check-tools)")
        return 2

    if not args.confirm_authorized:
        _print("[bold red]ERROR:[/] you must pass --confirm-authorized to start a scan")
        return 2

    # tool status (informational)
    _print("[*] Checking tool dependencies...", style="yellow")
    ToolPathValidator().check_all_tools(console=_console)

    # target validation
    validator = TargetValidator(scope_file=args.scope)
    try:
        target = validator.validate_and_normalize(args.target)
    except ValueError as e:
        _print(f"[bold red]Target rejected:[/] {e}")
        return 2

    # build settings
    settings = Settings(args)
    settings.target = target  # store the normalized hostname

    if _RICH and _console:
        ua_line = ""
        sel = getattr(settings, "ua_selector", None)
        if sel is not None:
            ua_line = f"\n[bold magenta]User-Agent:[/] {sel.describe()}"
        _console.print(Panel(
            f"[bold green]Target:[/] {settings.target}\n"
            f"[bold yellow]Mode:[/] {settings.mode}\n"
            f"[bold cyan]Threads:[/] {settings.threads}\n"
            f"[bold red]Rate limit:[/] {settings.rate_limit} req/s\n"
            f"[bold]Modules:[/] {', '.join(settings.modules)}"
            f"{ua_line}",
            title="Scan Configuration", border_style="blue"))

    # Typo-stop confirmation: require user to type the target hostname.
    # This is what kubectl, terraform destroy, etc. all do for a reason —
    # a single checkbox is theater. Bypass with --i-am-authorized
    # (intentionally awkward to type) only for CI / automation.
    if not getattr(args, "i_am_authorized", False):
        _print(f"\n[bold yellow]Type the target hostname to confirm "
               f"authorized scanning ([bold]{settings.target}[/]) or CTRL+C:[/]")
        try:
            typed = input("> ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            _print("\n[red]Aborted.[/]")
            return 0
        if typed != settings.target.lower():
            _print(f"[bold red]Target mismatch ('{typed}' != "
                   f"'{settings.target}'). Aborted.[/]")
            return 2

    # run!
    engine = ScannerEngine(settings)
    engine.run()
    return 0


def _issue_auth(args) -> int:
    """Side-channel helper: write a signed authorization file and exit."""
    from modules.exploit.authorization import (
        create_authorization, write_authorization,
    )
    if not args.verify_hostnames:
        _print("[bold red]ERROR:[/] --verify-issue-auth requires "
               "--verify-hostnames host1 [host2 ...]")
        return 2
    if args.verify_allow_destructive_auth and args.verify_max_safety != "destructive":
        _print("[bold red]ERROR:[/] --verify-allow-destructive-auth requires "
               "--verify-max-safety=destructive")
        return 2
    auth = create_authorization(
        engagement=args.verify_engagement,
        operator=args.verify_operator,
        hostnames=args.verify_hostnames,
        valid_days=args.verify_valid_days,
        max_safety_level=args.verify_max_safety,
        allow_destructive=args.verify_allow_destructive_auth,
        notes=args.verify_notes,
    )
    write_authorization(auth, args.verify_issue_auth)
    _print(f"[green]Wrote signed authorization to {args.verify_issue_auth}[/]")
    _print(f"  engagement: {auth.engagement}")
    _print(f"  operator:   {auth.operator}")
    _print(f"  hostnames:  {auth.hostnames}")
    _print(f"  expires:    {auth.expires_at}")
    _print(f"  max-safety: {auth.max_safety_level}")
    _print(f"  destructive-allowed: {auth.allow_destructive}")
    _print("\n[yellow]Keep the signing key safe (default "
           "~/.hunterpy/auth.key) — losing it invalidates this file.[/]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
