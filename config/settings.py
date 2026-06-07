"""Global configuration & settings management."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


SCAN_MODES = ("passive", "quick", "standard", "full", "stealth",
              "strict", "best-effort", "custom")


@dataclass
class Settings:
    """Central settings object passed to every module."""

    # --- Target ---
    target: str = ""
    target_list: Optional[str] = None
    scope_file: Optional[str] = None

    # --- Scan behavior ---
    mode: str = "standard"
    modules: List[str] = field(default_factory=list)
    threads: int = 10
    timeout: int = 30
    rate_limit: int = 10
    delay: float = 0.1

    # --- Authentication ---
    auth_url: Optional[str] = None
    username: Optional[str] = None
    username_list: Optional[str] = None
    password_list: Optional[str] = None

    # --- Network ---
    proxy: Optional[str] = None
    user_agent: str = "HunterPy/2.0 (+authorized-testing)"
    cookies: Optional[str] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)

    # --- User-Agent rotation ---
    # `user_agent` (above) holds the resolved primary UA for backwards
    # compatibility with modules that still read it directly. The
    # `UserAgentSelector` instance attached at `ua_selector` is what
    # callers SHOULD use when they want per-request rotation.
    user_agent_preset: Optional[str] = None
    user_agent_pool: List[str] = field(default_factory=list)
    user_agent_file: Optional[str] = None
    user_agent_strategy: str = "static"   # static | rotate-random | rotate-sequential
    ua_selector: object = None            # UserAgentSelector, set in __init__

    # --- Output ---
    output_dir: str = "./output"
    report_format: str = "all"
    verbose: bool = False
    no_color: bool = False

    # --- NVD CVE feed ---
    nvd_enabled: bool = True
    nvd_offline: bool = False
    nvd_api_key: Optional[str] = None
    nvd_cache_days: int = 1
    nvd_min_cvss: float = 4.0
    nvd_max_per_product: int = 5

    # --- DB ---
    db_path: str = "hunterpy.db"

    # --- Dork / OSINT options ---
    dorks_active: bool = False               # opt-in: scrape Google for real
    confirm_dork_scraping: bool = False      # second opt-in (defense-in-depth)
    dork_max_queries: int = 5                # cap distinct dorks scraped
    dork_max_results: int = 10               # cap results per dork
    dork_rate_limit: float = 0.2             # requests / second when scraping
    dork_templates: list = field(default_factory=list)   # filter to these
    dork_extra: str = ""                     # extra keywords appended to every dork

    # --- SQLMap intensity overrides ---
    # Per-mode (level, risk) lives in the sqlmap module. These two fields
    # let the operator override them at the CLI without changing mode.
    sqlmap_level: Optional[int] = None
    sqlmap_risk: Optional[int] = None

    # --- Auth testing ---
    # `default_cred_check` is the new lightweight default (20 common
    # pairs, single request each, reports `weak_credentials`/`weak_password_policy`).
    # `enable_bruteforce` flips Hydra on as an opt-in for engagements
    # that explicitly scope credential brute-forcing.
    enable_bruteforce: bool = False

    # --- Verification (post-classification safe exploit confirmation) ---
    # The verifier is OFF by default. It only runs when:
    #   * `--verify` is passed AND
    #   * a signed authorization file (`--verify-auth-file`) covers the target.
    # See docs/VERIFICATION.md for the legal/operational design.
    verify_enabled: bool = False
    verify_auth_file: Optional[str] = None
    verify_non_interactive: bool = False
    verify_allow_destructive: bool = False
    verify_rate_limit_per_sec: float = 0.5
    verify_only_types: list = field(default_factory=list)
    verify_max_findings: int = 50
    verify_collaborator_url: Optional[str] = None    # external interactsh-style URL
    write_poc: bool = False                           # emit poc.sh/poc.py per confirmed finding

    # ----------------------------------------------------------------
    def __init__(self, args=None, **overrides):
        # Reset to dataclass defaults (without invoking @dataclass __init__,
        # since we're overriding it).
        from dataclasses import fields, MISSING
        for f in fields(self):
            if f.default is not MISSING:
                setattr(self, f.name, f.default)
            elif f.default_factory is not MISSING:        # type: ignore[misc]
                setattr(self, f.name, f.default_factory())  # type: ignore[misc]
            else:
                setattr(self, f.name, None)

        if args is not None:
            self._load_from_args(args)
        for k, v in overrides.items():
            setattr(self, k, v)

        os.makedirs(self.output_dir, exist_ok=True)
        self._apply_mode_preset()
        self._build_ua_selector()

    # ----------------------------------------------------------------
    def _load_from_args(self, args) -> None:
        self.target         = getattr(args, "target", "") or ""
        self.target_list    = getattr(args, "target_list", None)
        self.scope_file     = getattr(args, "scope", None)
        self.mode           = getattr(args, "mode", "standard")
        self.modules        = list(getattr(args, "modules", None) or [])
        self.threads        = getattr(args, "threads", 10)
        self.timeout        = getattr(args, "timeout", 30)
        self.rate_limit     = getattr(args, "rate_limit", 10)
        self.delay          = getattr(args, "delay", 0.1)
        self.auth_url       = getattr(args, "auth_url", None)
        self.username       = getattr(args, "username", None)
        self.username_list  = getattr(args, "username_list", None)
        self.password_list  = getattr(args, "password_list", None)
        self.proxy          = getattr(args, "proxy", None)
        self.user_agent     = getattr(args, "user_agent", None) or self.user_agent
        # UA pool/preset/file/strategy. The selector itself is built in
        # _build_ua_selector() after _load_from_args returns. We coerce
        # everything to the right type defensively — tests sometimes
        # pass `MagicMock(...)` which makes `getattr(..., None)` return
        # a truthy mock object rather than None.
        def _str_or_none(v):
            return v if isinstance(v, str) and v else None
        self.user_agent_preset   = _str_or_none(getattr(args, "user_agent_preset", None))
        raw_pool = getattr(args, "user_agent_pool", None)
        self.user_agent_pool     = [x for x in (raw_pool or []) if isinstance(x, str)]
        self.user_agent_file     = _str_or_none(getattr(args, "user_agent_file", None))
        raw_strategy = getattr(args, "user_agent_strategy", "static")
        self.user_agent_strategy = raw_strategy if isinstance(raw_strategy, str) else "static"
        self.cookies        = getattr(args, "cookies", None)
        self.output_dir     = getattr(args, "output", "./output")
        self.report_format  = getattr(args, "format", "all")
        self.verbose        = getattr(args, "verbose", False)
        self.no_color       = getattr(args, "no_color", False)
        # NVD knobs (optional)
        if getattr(args, "no_nvd", False):
            self.nvd_enabled = False
        if getattr(args, "nvd_offline", False):
            self.nvd_offline = True
        if getattr(args, "nvd_api_key", None):
            self.nvd_api_key = args.nvd_api_key

        # parse --headers "K: V" "K2: V2"
        raw_headers = getattr(args, "headers", None) or []
        for raw in raw_headers:
            if ":" in raw:
                k, _, v = raw.partition(":")
                self.custom_headers[k.strip()] = v.strip()

        # Dork options
        self.dorks_active           = bool(getattr(args, "dorks_active", False))
        self.confirm_dork_scraping  = bool(getattr(args, "confirm_dork_scraping", False))
        self.dork_max_queries       = int(getattr(args, "dork_max_queries", 5))
        self.dork_max_results       = int(getattr(args, "dork_max_results", 10))
        self.dork_templates         = list(getattr(args, "dork_templates", None) or [])
        self.dork_extra             = getattr(args, "dork_extra", "") or ""

        # SQLMap overrides
        self.sqlmap_level = getattr(args, "sqlmap_level", None)
        self.sqlmap_risk  = getattr(args, "sqlmap_risk", None)

        # Auth testing
        self.enable_bruteforce = bool(getattr(args, "enable_bruteforce", False))

        # Verification options
        self.verify_enabled              = bool(getattr(args, "verify", False))
        self.verify_auth_file            = getattr(args, "verify_auth_file", None)
        self.verify_non_interactive      = bool(getattr(args, "verify_non_interactive", False))
        self.verify_allow_destructive    = bool(getattr(args, "verify_allow_destructive", False))
        self.verify_rate_limit_per_sec   = float(getattr(args, "verify_rate_limit_per_sec", 0.5))
        self.verify_only_types           = list(getattr(args, "verify_only_types", None) or [])
        self.verify_max_findings         = int(getattr(args, "verify_max_findings", 50))
        self.verify_collaborator_url     = getattr(args, "verify_collaborator_url", None)
        self.write_poc                   = bool(getattr(args, "write_poc", False))

    # ----------------------------------------------------------------
    def _apply_mode_preset(self) -> None:
        """If the user didn't pick modules manually, apply the mode preset."""
        presets = {
            "passive": {
                # Strictly non-intrusive: standard HTTP fetches, DNS, WHOIS,
                # JS source scan, common-path probe, dork suggestions
                # (preview only — no Google scraping unless explicitly opted in).
                "threads": 5, "rate_limit": 5,
                "modules": ["fingerprint", "headers", "ssl",
                            "dns", "whois", "surface", "js", "js_vulns",
                            "endpoints", "dorks", "symfony"],
            },
            "quick": {
                "threads": 5, "rate_limit": 5,
                "modules": ["headers", "ssl", "fingerprint",
                            "gobuster", "nikto", "symfony"],
            },
            "standard": {
                "threads": 10, "rate_limit": 10,
                "modules": ["headers", "ssl", "fingerprint", "endpoints",
                            "nikto", "gobuster", "ffuf",
                            "cors", "sqlmap", "symfony",
                            "default_creds"],
            },
            "full": {
                "threads": 20, "rate_limit": 20,
                "modules": ["headers", "ssl", "fingerprint", "endpoints",
                            "dns", "whois", "surface", "js", "js_vulns",
                            "dorks", "symfony",
                            "nuclei", "nikto", "gobuster", "ffuf",
                            "wfuzz", "cors", "sqlmap",
                            "default_creds", "hydra"],
            },
            "stealth": {
                "threads": 2, "rate_limit": 1, "delay": 2.0,
                "modules": ["headers", "ssl", "fingerprint",
                            "nikto", "gobuster", "symfony",
                            "default_creds"],
            },
            # `strict` = full scan, but the engine fails-fast at start
            # if any selected module's external tool is missing. Same
            # module set as `full`; the strictness is enforced by
            # ScannerEngine.run() via core.module_coverage.enforce_strict_mode.
            "strict": {
                "threads": 20, "rate_limit": 20,
                "modules": ["headers", "ssl", "fingerprint", "endpoints",
                            "dns", "whois", "surface", "js", "js_vulns",
                            "dorks", "symfony",
                            "nuclei", "nikto", "gobuster", "ffuf",
                            "wfuzz", "cors", "sqlmap",
                            "default_creds", "hydra"],
            },
            # `best-effort` = same as standard but the operator has
            # acknowledged the fallback paths are degraded. The banner
            # still prints; the scan still runs.
            "best-effort": {
                "threads": 10, "rate_limit": 10,
                "modules": ["headers", "ssl", "fingerprint", "endpoints",
                            "nikto", "gobuster", "ffuf",
                            "cors", "sqlmap", "symfony",
                            "default_creds"],
            },
            "custom": {},
        }

        from dataclasses import fields, MISSING
        defaults = {f.name: (f.default if f.default is not MISSING else None)
                    for f in fields(self)}

        preset = presets.get(self.mode, {})
        if not self.modules and "modules" in preset:
            self.modules = list(preset["modules"])
        # Only overwrite fields that still hold their dataclass default
        for key, value in preset.items():
            if key == "modules":
                continue
            current = getattr(self, key, None)
            if current == defaults.get(key):
                setattr(self, key, value)

    # ----------------------------------------------------------------
    def _build_ua_selector(self) -> None:
        """Construct the ``UserAgentSelector`` from the resolved fields.

        Precedence (handled by ``UserAgentSelector.from_args``):
          1. explicit pool list  (--user-agent-pool)
          2. pool file           (--user-agent-file)
          3. preset name         (--user-agent-preset)
          4. single UA string    (--user-agent)
          5. dataclass default   (the honest-disclosure UA)
        """
        # Import here to avoid a circular import at module load time
        # (user_agents.py doesn't import settings, but keeping the import
        # local is defensive against future drift).
        from config.user_agents import UserAgentSelector, DEFAULT_USER_AGENT

        # If user_agent is still the default and a preset/pool/file is
        # set, prefer those — otherwise the single user_agent wins.
        single = (self.user_agent
                  if self.user_agent and self.user_agent != DEFAULT_USER_AGENT
                  else None)
        try:
            sel = UserAgentSelector.from_args(
                single=single,
                preset=self.user_agent_preset,
                pool=self.user_agent_pool or None,
                pool_file=self.user_agent_file,
                strategy=self.user_agent_strategy,
            )
        except (ValueError, FileNotFoundError) as e:
            # Fail loud but don't crash the whole scan — fall back to the
            # default UA and let the engine log the error.
            import logging
            logging.getLogger("hunterpy.ua").error(
                "user-agent configuration error (%s) — falling back to default",
                e)
            sel = UserAgentSelector([DEFAULT_USER_AGENT], strategy="static")

        self.ua_selector = sel
        # Keep `user_agent` in sync with the selector's primary UA so old
        # callers still see something sensible.
        self.user_agent = sel.current()
