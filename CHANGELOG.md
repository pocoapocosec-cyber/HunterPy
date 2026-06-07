# Changelog

All notable changes to HunterPy are tracked here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.6.0] — 2026-06-07

Response to a detailed external critique. Four bundles delivered:
quick wins, pentest-tradecraft improvements, the manual-PoC writer,
and an architectural refactor.

### Added — Quick wins

**Tool-coverage transparency (`core/module_coverage.py`)**

- Per-(module, package-manager) catalogue mapping each scanner module
  to its external tool and whether a Python fallback exists.
- `build_coverage_report()` produces a per-scan snapshot with four
  tiers: `full` (tool present), `fallback` (tool missing but degraded
  Python path runs), `skipped` (tool missing + no fallback), `native`
  (pure-Python module).
- Warning banner printed **at scan start**, summary printed **at scan
  end** — no more "I thought I ran nuclei" incidents.
- New `--mode strict` fails-fast at scan start if any selected module
  isn't at `full` coverage; new `--mode best-effort` documents
  intentional acceptance of fallbacks.
- Coverage report serialised into `session.metadata["coverage"]` and
  surfaced in the markdown report frontmatter.
- 20 tests in `tests/test_module_coverage.py`.

**Classifier explainability (`classifiers/finding_classifier.py`)**

- Every finding now carries a structured `classification_explanation`
  dict alongside the legacy `classification_reason` string:
  ```json
  {
    "final_class": "INTERESTING",
    "confidence": 0.85,
    "primary_reason": "module confirmed the finding",
    "factors": [
      {"kind": "module_hint", "field": "confirmed", "weight": 1.0},
      {"kind": "signature_pack", "pack": "interesting_patterns.json",
       "matched_entry": {...}, "weight": 0.8}
    ],
    "context_chains": ["symfony_full_pwnage"],
    "human_explanation": "Classified as INTERESTING (module confirmed
     the finding). Primary signal: the producing module asserted
     `confirmed` on the finding. Participates in attack chain(s):
     symfony_full_pwnage."
  }
  ```
- Five factor kinds: `module_hint`, `type_table`, `signature_pack`,
  `severity_score`, `context_rule`. Every classification path now
  contributes at least one factor.
- 9 tests in `tests/test_classifier_explainability.py`.

**YAML frontmatter on the markdown report**

- Reports now start with a machine-readable YAML block (scan_id,
  target, mode, generated_at, findings_summary by severity + by class,
  attack_chains with steps, verification_summary).
- Hand-rolled emitter — no PyYAML dependency added.
- LLMs (ChatGPT/Claude/Gemini) parse it cleanly; CI pipelines can grep
  it for summary counts without parsing the whole report.
- 6 tests in `tests/test_markdown_frontmatter.py`.

**CSP on the interactive HTML report**

- Single-file HTML reports now carry a `Content-Security-Policy` meta
  tag with `default-src 'none'` and a SHA-256 hash of the inline script
  (`script-src 'sha256-…'`). No `'unsafe-inline'`, no `'unsafe-eval'`.
- `connect-src`, `form-action`, `base-uri`, `frame-ancestors` all
  locked to `'none'` — defends against the "report opened from
  attacker-controlled directory" scenario.
- 5 tests in `tests/test_html_report_csp.py`, including one that
  re-computes the hash from the actual emitted script body so any
  edit to the JS that forgets to bump the CSP will fail-loud.

### Added — Pentest tradecraft

**Per-mode SQLMap intensity + CLI overrides**

- New `_MODE_LEVEL_RISK` table in `modules/injection/sqlmap_module.py`:
  `passive`/`quick`/`stealth`/`best-effort`=`(1,1)`,
  `standard`=`(2,1)`, `full`/`strict`=`(3,2)`.
- New `--sqlmap-level` / `--sqlmap-risk` CLI flags for per-scan
  overrides, clamped to sqlmap's valid 1-5 / 1-3 ranges.
- 10 tests in `tests/test_sqlmap_intensity.py`.

**`default_creds` module — Hydra alternative for the common case**

- `modules/auth_testing/default_cred_check.py` — single-shot audit of
  20 documented default credential pairs against a discovered login
  endpoint. Stops at the first hit per endpoint. Caps at 3 endpoints.
  Stores SHA-256 hash of the matched pair, never the plaintext.
- Wired into the `standard`/`full`/`stealth`/`strict`/`best-effort`
  presets and Phase 4 (auth). Hydra remains available but now requires
  `--enable-bruteforce` (off by default).
- 16 tests in `tests/test_default_creds.py`.

### Added — Manual PoC writer (`modules/exploit/poc_writer.py`)

- New `--write-poc` flag on the verifier. For each CONFIRMED finding,
  emits three files into the evidence bundle:
  - `poc.sh` — single-curl reproducer, mode 0700
  - `poc.py` — stdlib-only urllib reproducer (no `requests` dep), 0700
  - `poc.md` — README explaining usage, safety, and cleanup
- Exit code contract: `0` = issue still reproducible (fix not in
  place), `1` = status diverged (issue may be fixed), `2` = network
  failure. Makes the PoCs drop-in regression checks for the client's
  CI pipeline.
- Each PoC carries the authorization-file context (engagement,
  operator, expires_at, consent UUID) and the `X-HunterPy-Verify`
  marker so blue teams can correlate.
- Explicitly does NOT generate: webshells, persistence, pivoting,
  fuzzing loops, or any modification of target state beyond the one
  request the verifier already sent.
- 13 tests in `tests/test_poc_writer.py` covering: only fires on
  CONFIRMED, never on inconclusive/skipped/error; single curl
  invocation; no while/for loops; correct exit codes; no secrets leak
  into emitted scripts; README documents safety constraints.

### Added — Architectural refactor

**Module dependency graph (`requires_modules`)**

- `ModuleDep` extended with `requires_modules: tuple` field.
- `sqlmap` now declares `requires_modules=("endpoints",)`. When
  endpoints is missing from the plan or skipped at runtime, sqlmap
  skips with a clear message instead of running on empty input.
- `unmet_module_requirements(module, available, completed)` helper.
- Engine consults the helper in `_phase_exploitation`. Other phases
  will adopt the same pattern as we add more cross-module deps.
- 5 tests added to `test_module_coverage.py`.

**Engine split — `ScanPersistence` + `ProgressTracker`**

- `core/scan_persistence.py`: wraps DB checkpoint writes. Returns
  `bool` instead of raising — checkpoint failures observable via
  return value + log, never abort the scan.
- `core/progress_tracker.py`: thread-safe counters (`started`,
  `completed`, `failed`, `percent`) + `snapshot()` for API responses.
  Caught a real re-entrant lock bug in code review (snapshot called
  the `percent` property while holding the lock).
- `ScannerEngine._safe_run` is now ~10 lines of orchestration; DB +
  progress concerns live in the helpers.
- 12 tests in `tests/test_scan_persistence_and_progress.py`.

**Standard error-handling decorator (`utils/module_safe.py`)**

- `@module_safe(fallback="skip"|"empty"|"raise", log_level="...")`
  decorator for module `run()` methods.
- Replaces the "every module catches Exception differently" pattern
  with a single declarative policy. Crashes now produce a consistent
  fallback dict + a log entry at the configured level + the error
  string in the returned dict's `error` field for report surfacing.
- Applied to `SymfonyDetector.run` and `DefaultCredCheckModule.run`
  as the first adopters; more modules to be migrated as we touch them.
- 10 tests in `tests/test_module_safe.py`.

### Push-back & honest scope limits

The same critique-thread asked (again) for "auto-PoC on critical and
high findings" — restated from the original auto-shell ask. I refused
again for the same reasons documented in v2.3's `docs/VERIFICATION.md`:
auto-firing exploitation traffic on every CRITICAL finding is the
auto-exploit feature in different wrapping, and would re-introduce all
the SOW/CFAA/SOC-confusion risks the verification subsystem was
designed to avoid.

The manual PoC writer above is the safe equivalent. The operator runs
the script. Nothing fires automatically. Tests assert it.

Also pushed back on:
- **Removing `--dorks-active`** — kept, still double-gated.
- **`conflicts: ["symfony"]` in the dep graph** — declined; built
  `requires_modules` (hard dep) only. Soft "prefers artifacts from"
  TBD when there's a concrete need.

### Test counts (current)

- **382 Python core tests** passing (was 281).
- **23 FastAPI backend tests** passing (unchanged).


## [2.5.0] — 2026-06-07

### Added — User-Agent rotation (`config/user_agents.py`)

The previous `--user-agent` flag took a single string. v2.5 turns that
into a small selection subsystem with presets, file pools, and three
rotation strategies — useful for **WAF testing**, **UA-conditional
rendering** verification, and **bot-detection evaluation**. The default
behaviour is unchanged: every request still identifies HunterPy in the
target's logs unless the operator explicitly overrides it.

**Design notes baked into the code:**

- The default UA remains the honest disclosure string
  (`HunterPy/2.0 (+authorized-testing)`). That's what makes the tool
  defensible under most SOWs — many engagements *require* identifiable
  scanner traffic. Operators have to opt in to disguise.
- Verification probes always append `verify/<consent_marker>` to
  whatever UA they're using, so the `X-HunterPy-Verify` correlation
  marker survives even when the base UA looks like Chrome.
- Bot-impersonation presets (Googlebot, Bingbot) are tagged
  `noisy_impersonation`. The CLI listing flags them in red and the
  description spells out the legal/operational risk.
- Rotation requested on a pool of size 1 collapses to `static` with a
  warning — it would otherwise be a confusing no-op.

**New components:**

- `config/user_agents.py` (~280 LOC):
  - `DEFAULT_USER_AGENT`, `UAPreset`, `UserAgentSelector`.
  - 17 named presets — Chrome/Firefox/Safari/Edge on the three major
    desktop platforms, mobile Safari (iOS), Chrome (Android), `curl`,
    `wget`, plus `desktop-browsers` / `mobile-browsers` / `all-browsers`
    multi-UA bundles and the two impersonation presets.
  - `load_pool_file(path)` — line-based pool loader, `#` comments
    allowed, empty/missing files raise loudly.
  - `UserAgentSelector` with three thread-safe strategies (`static`,
    `rotate-random`, `rotate-sequential`).
  - `UserAgentSelector.from_args()` factory enforcing the documented
    precedence (pool > file > preset > single > default).
- `config/settings.py` — new fields `user_agent_preset`,
  `user_agent_pool`, `user_agent_file`, `user_agent_strategy`, plus
  `ua_selector` (a live `UserAgentSelector`). `_build_ua_selector()`
  runs at `Settings.__init__` time and fails *closed*: any
  configuration error falls back to the default UA, logs an error, and
  does not crash the scan. `MagicMock`-tolerant arg coercion so
  existing module tests still work.
- `utils/http_client.py` — new `http_get_with_settings(settings, url,
  **kw)` helper that consults `settings.ua_selector` per call when the
  strategy isn't `static`. Modules can opt into rotation without
  touching every existing call site.
- `modules/custom/endpoint_crawler.py`, `surface_map.py`,
  `symfony_detector.py` — switched their high-volume request loops over
  to per-request `selector.next()`. The baseline analyzer
  *deliberately* stays on the static UA (consistent UA across
  baseline + test is what makes the comparison meaningful).
- `modules/exploit/probes/base.py` — `_consent_headers()` now picks the
  rotated UA but always appends `verify/<consent_marker>` so the
  blue-team correlation marker survives rotation.
- `main.py`:
  - New CLI flags: `--user-agent-preset`, `--user-agent-pool`,
    `--user-agent-file`, `--user-agent-strategy`, `--list-user-agents`.
  - Existing `--user-agent` flag kept for backward compatibility.
  - The "Scan Configuration" rich panel now shows the active UA
    strategy + pool size + primary UA.
- `gui/backend/routes/misc.py` — new `GET /api/user-agents` returning
  the full preset catalogue + supported strategies for the React
  frontend's dropdown. Categorisation lets the UI badge impersonation
  presets with a warning icon.
- `gui/backend/services/scan_manager.py` — passes
  `user_agent_preset` / `user_agent_pool` / `user_agent_file` /
  `user_agent_strategy` from the REST options blob into `Settings`.

### Added — 36 new tests

- `tests/test_user_agents.py` (34 tests) — preset catalogue invariants,
  pool-file loader (comments, blanks, missing/empty edge cases),
  selector strategies (static/sequential/random), thread-safety of the
  sequential rotator under 8 concurrent worker threads, `from_args`
  precedence rules, rotation-collapse-to-static for size-1 pools,
  Settings integration (preset/pool/file/single/default paths plus
  graceful fall-back on bad input), `http_get_with_settings` UA
  selection, verification probe consent-marker preservation.
- `gui/backend/tests/test_api.py` (+2) — `/api/user-agents` catalogue
  shape, end-to-end `POST /api/scans + start` with
  `user_agent_preset: chrome-windows` capturing the resulting Settings
  object and asserting `ua_selector` is populated.

### Test counts (current)

- **281 Python core tests** passing (was 247).
- **23 FastAPI backend tests** passing (was 21).


## [2.4.0] — 2026-06-07

### Added — Transparent tool installer (`--install-tools`)

The detection mechanism in `--check-tools` already told operators what
was missing; v2.4 adds the ability to *act* on that information, with
guard-rails that pentest firms' security teams will accept.

**Design principles (read `config/tool_installer.py` before
"improving"):**

- **Dry-run by default.** `--install-tools` prints the full plan and
  exits. Nothing happens until you pass `--install-tools-confirm`.
- **No silent privilege escalation.** Steps that need root run via
  `sudo`. The installer pre-checks `sudo -n -v`; if cached credentials
  aren't valid, sudo-requiring steps are forced into dry-run mode and a
  loud message tells the operator to run `sudo -v` first. The installer
  itself **never** prompts for a password.
- **Pinned versions for everything we can pin.** `sqlmap==1.8.10`,
  `wfuzz==3.1.0`, gobuster/ffuf/nuclei pinned to specific git tags.
  All pins live in `PINNED_VERSIONS` in one place.
- **Go binaries are documentation-only.** `go install ...@<tag>` is
  printed for the operator to run, never auto-executed. We don't
  verify Go-module checksums and won't pretend to.
- **Idempotent and reproducible.** Re-running with everything installed
  prints "already installed" per tool and rewrites the lockfile.
- **Platform-aware.** Detects apt / brew / pacman / apk and builds the
  appropriate plan per (tool, package manager) combination.
- **Lockfile output.** Every run writes `tools.lock.json` with the
  detected platform, the install method per tool, the resolved version,
  and the absolute path on disk. Diff it between runs in CI.

**New CLI flags:**

| Flag                              | Purpose                                              |
|-----------------------------------|------------------------------------------------------|
| `--install-tools`                 | Plan the install (dry-run by default).               |
| `--install-tools-confirm`         | Actually execute the plan.                           |
| `--install-tools-only TOOL ...`   | Restrict to a subset of tools.                       |
| `--install-tools-optional`        | Include nmap/curl/whatweb in the plan.               |
| `--install-tools-lockfile PATH`   | Override lockfile path (default `./tools.lock.json`).|

**New components:**

- `config/tool_installer.py` (~420 LOC) — `PINNED_VERSIONS`, platform
  detection, per-(tool, pkg-mgr) plan builders, `execute_plan`,
  `run_installer` orchestrator, lockfile reader/writer.
- `_probe_user_site_paths()` — handles the common case where
  `pip install --user` succeeds but `~/.local/bin` isn't on `PATH`.
  The installer reports success with a warning instead of falsely
  saying "install failed".
- 30 new tests in `tests/test_tool_installer.py` covering: every pinned
  version is concrete; each plan builder emits the right argv per
  package manager; dry-run never invokes subprocess; manual-only (Go)
  plans never execute even with `--install-tools-confirm`; sudo steps
  are refused when sudo isn't valid; user-site probe finds off-PATH
  installs; lockfile round-trips.

### Test counts (current)

- **247 Python core tests** passing (was 217).
- **21 FastAPI backend tests** passing (unchanged).


## [2.3.0] — 2026-06-07

### Added — Safe verification subsystem (`modules/exploit/`)

A new Phase 6 (post-classification) that runs **safe, operator-gated
proof-of-exploitability probes** against `INTERESTING` / `CRITICAL` /
`HIGH` findings. The verifier is OFF by default. Read
[`docs/VERIFICATION.md`](docs/VERIFICATION.md) before turning it on.

What it *is*: per-finding, least-invasive verification with full
evidence capture, signed-authorization scope, per-host typo-stop, WAF
backoff, secret redaction, and a per-finding `[y]/[n]/[a]/[q]` prompt.

What it *isn't*: an exploitation framework. The verifier deliberately
does **not** drop webshells, upload `.php`/`.phtml`/`.phar` payloads,
brute-force credentials, pivot, or persist anything. Operators who need
those should use a real C2 framework (Sliver / Mythic / Cobalt Strike)
under explicit SOW terms. This was a conscious design decision; see
`docs/VERIFICATION.md` § "Things the verifier deliberately doesn't do".

New components:

- **`modules/exploit/authorization.py`** — HMAC-SHA256-signed
  authorization JSON file with hostname scope (fnmatch globs), expiry
  timestamp, max safety level (`read_only` < `noisy_read` <
  `trivial_write` < `destructive`), and `allow_destructive` flag.
  Signing key lives in `$HUNTERPY_AUTH_KEY` or `~/.hunterpy/auth.key`
  (mode 0600). Verifier refuses to run with an expired, tampered, or
  out-of-scope authorization.
- **`modules/exploit/results.py`** — `VerificationResult`,
  `VerificationStatus` (`confirmed` / `inconclusive` / `safe_failed` /
  `skipped` / `error`), `SafetyLevel`, `HttpExchange` dataclasses.
- **`modules/exploit/collaborator.py`** — OOB callback receiver.
  Defaults to a `LocalCollaborator` HTTP listener on `127.0.0.1`;
  `--verify-collaborator-url` points at an external interactsh-style
  recorder for engagements where the target can't reach the operator's
  box.
- **`modules/exploit/evidence.py`** — writes a per-finding bundle to
  `<output>/verification/<finding_uid>/` containing `result.json`,
  `proof.txt`, `authorization.json`, and one `.http` file per
  request/response pair. Captured bodies are passed through a
  credential-redaction filter (`APP_SECRET`, `DATABASE_URL`,
  `OAUTH_*_SECRET`, `AKIA...`, etc.) that replaces secret values with
  `<REDACTED-sha256:<first16>>` fingerprints — so the bundle proves the
  secret was exposed without storing it.
- **`modules/exploit/probes/`** — per-finding-type probe classes,
  registered via the `@register_probe(type, ...)` decorator. Shipped
  probes:
  - `SymfonyProfilerExposedProbe` — fetches `/_profiler/`, looks for
    toolbar markup + visible request tokens.
  - `SymfonyProfilerPhpinfoProbe` — fetches `/_profiler/phpinfo`,
    detects sensitive env-var names, SHA-256s the values.
  - `SymfonyProfilerLFIProbe` — reads `/etc/hostname` via the
    `open?file=` handler (boring, sufficient proof, no PII).
  - `SymfonyAppEnvInjectionProbe` — sends `?+--env=dev` and diffs the
    response against the baseline (CVE-2024-50340 pattern).
  - `SymfonyExposedCredentialsProbe` — re-fetches the originally-flagged
    URL and confirms credential patterns are still present.
  - `GitExposedProbe` — confirms `.git/HEAD` returns a valid git ref.
  - `EnvExposedProbe` — confirms the URL parses as dotenv format.
  - `AdminPanelProbe` — confirms the admin URL is reachable and renders
    login UI. **Never** submits credentials.
  - `SourceMapExposedProbe` — confirms the URL serves a v3 source map.
  - `UnrestrictedUploadProbe` — uploads a **plain `.txt` marker** (not
    PHP / phtml / phar / asp / jsp / exe), GETs it back, attempts a
    DELETE, and reports `cleanup_successful` honestly.
- **`modules/exploit/verifier.py`** — orchestrator. Per-finding
  interactive prompts (`y` / `n` / `a` / `q`) unless
  `--verify-non-interactive`. Re-checks scope + safety per-finding (not
  just at scan start). Rate-limits between probes (default 0.5/sec).
  Aborts the whole phase on 429 / WAF-block heuristics. Catches probe
  panics into `VerificationStatus.ERROR`.
- **`core/scanner_engine.py`** — new Phase 6 wired in. Runs only when
  `--verify` is set and `--verify-auth-file` resolves.
- **`core/markdown_report.py`** — new "Verification Results" table in
  the AI-pasteable Markdown report, with status glyphs and a pointer to
  the evidence bundle.
- **CLI** — eight new `--verify-*` flags + the `--verify-issue-auth`
  side-channel for generating signed authorization files.

### Added — 59 new tests

- `tests/test_verification_authorization.py` (9 tests) — HMAC roundtrip,
  tamper detection, expiry, hostname glob scope, safety-level cap,
  destructive opt-in.
- `tests/test_verification_evidence.py` (10 tests) — secret redaction
  patterns, safe-filename traversal defence, full bundle structure.
- `tests/test_verification_probes.py` (16 tests) — registry membership,
  per-probe confirmed / inconclusive / safe_failed paths,
  no-credential-leak assertions, static check that the upload probe
  source contains no executable extensions.
- `tests/test_verifier_orchestrator.py` (17 tests) — eligibility filter,
  evidence persistence, out-of-scope refusal, destructive double-gate,
  probe-crash handling, WAF backoff, interactive prompt branches,
  `--verify-only-types`, `--verify-max-findings`.
- `tests/test_verification_collaborator.py` (7 tests) — token
  uniqueness, local listener round-trip, factory selection.

### Documentation

- **`docs/VERIFICATION.md`** — full design doc: threat model, control
  flow, authorization-file schema, safety levels, evidence-bundle
  layout, redaction policy, collaborator protocol, instructions for
  adding new probes, and a *what-we-deliberately-don't-do* matrix that
  the team uses to push back on feature requests for auto-RCE.

### Test counts (current)

- **217 Python core tests** passing (was 158).
- **21 FastAPI backend tests** passing (unchanged).
- TypeScript / Java / Vite builds unchanged.


## [2.2.0] — 2026-06-07

### Added — Threat-intel integration of three SECREP reports
Three real-world Symfony pentest reports (preserved at
`docs/threat-intel/SECREP-*.pdf`) were converted into a structured intel
pack and wired into every layer of the detection pipeline.

- **`signatures/intel/symfony_exposure.json`** — declarative intel pack:
  framework fingerprints (header / cookie / body / path), 8 passive
  exposure paths with status + body matchers, 2 query-string tricks,
  13 credential-exposure patterns, 5 CVE entries, and 1 attack-chain
  recipe with predicates for the context graph.
- **`modules/custom/symfony_detector.py`** — new passive module wired
  into the `phase1_recon` pipeline + every default mode preset
  (`passive`, `quick`, `standard`, `full`, `stealth`). Probes the
  intel-pack paths, fingerprints Symfony from headers / body, and scans
  the landing page for credential leaks (values redacted before being
  written to disk).
- **`tech_fingerprint`** now recognises Symfony via `X-Debug-Token`,
  `X-Debug-Token-Link`, `X-Symfony-Cache` headers + body markers
  (`Symfony Profiler`, `sfWebDebugToolbar`).
- **Classifier** — 14 new finding types added to `INTERESTING_TYPES`
  so every Symfony / ImageMagick / EOL-PHP / file-upload finding is
  escalated automatically.
- **Context graph** — 3 new attack chains: `symfony_full_pwnage`
  (profiler + leak), `symfony_dev_mode_in_prod` (app_dev or env
  injection + profiler), `imagemagick_upload_rce_recipe`
  (upload + vulnerable ImageMagick / EOL PHP).
- **PoC generator** — 7 new builders covering every Symfony type,
  every PoC cites the source SECREP report under `docs/threat-intel/`.
- **Impact analyzer** — every new finding type gets a data-at-risk
  mapping + compliance hints.
- **`signatures/dork_templates.json`** — new `symfony_exposure`
  template renders 8 target-restricted Google dorks per scan.
- **`signatures/vulnerability_db.json`** — extended with bundled
  offline entries for CVE-2016-3714, CVE-2021-4219, CVE-2024-50340,
  GHSA-pv9j-c53q-h433.
- **`signatures/interesting_patterns.json`** — 11 new patterns covering
  `_profiler`, `app_dev.php`, `parameters.yml`, `?+--env=` injection,
  EOL-PHP version strings, and ImageMagick 6.x.
- **`docs/threat-intel/`** — bundled source PDFs so future readers can
  trace any finding back to the originating incident.
- **28 new unit tests** (`test_symfony_detector.py` +
  `test_symfony_intel_wiring.py`) covering the detector itself, the
  intel-pack shape, classifier/chain/PoC/impact wiring, mode presets,
  CLI choices, and the bundled CVE DB.

### Verified end-to-end
Against a simulated vulnerable Symfony target (`fake_get` patch):
- 3 individual Symfony findings detected (`profiler_exposed`,
  `profiler_phpinfo`, `profiler_lfi`) — all classified INTERESTING / CRITICAL
- `chain_symfony_full_pwnage` fires automatically and links the
  underlying findings
- The fingerprint marker correctly stays as FALSE_ALARM
  (informational only)

## [2.1.0] — 2026-06-07

### Added
- **FastAPI REST backend** (`gui/backend/`) — wraps `ScannerEngine` in
  a thread-per-scan manager. 25 endpoints matching the contract in
  `gui/frontend/src/lib/api/endpoints.ts`. OpenAPI/Swagger at `/docs`.
  21 unit tests using `fastapi.testclient`. Includes `_FakeEngine`
  pattern so tests don't touch the network.
- **Burp Suite XML exporter** (`reporting/burp_exporter.py`) — render
  HunterPy findings as Burp's native issue-import format. Use with
  `--format burp` and import via Burp's *Project options ▸ Misc ▸ Issue
  import*. Works on Burp Pro and Community; no extension install
  required.
- **Burp Suite extension** (`gui/burp-extension/`) — Montoya-API Java
  extension adding a "HunterPy" tab. Loads JSON reports, sends URLs to
  Repeater, emits AuditIssues into the Site Map. ~750 LOC + a 200-line
  dependency-free JSON parser; no Jackson / Gson.
- **Dockerfile + docker-compose.yml** — multi-stage build with
  nmap / nikto / sqlmap / hydra / gobuster / ffuf from apt and nuclei
  built from pinned go source. Non-root (uid 1000). `tini` as PID 1 so
  Ctrl-C reaches the python process. Healthcheck calls
  `main.py --check-tools`.
- 15 new unit tests for the Burp exporter (XML validity, severity
  mapping, CDATA escaping, PoC inclusion).
- 2 new regression tests for the OSV CVSS-vector parsing bug.
- 2 new regression tests for the surface_map `lstrip` and bs4-fallback
  form-parser bugs.

### Fixed (project-wide audit pass)
- `modules/custom/surface_map.py::extract_subdomains` used
  `str.lstrip("www.")` which strips any leading `w`/`.` character
  (turning `"web.example.com"` into `"eb.example.com"`). Replaced with
  a proper prefix check.
- `modules/custom/surface_map.py::extract_forms` regex fallback rewrote
  form bodies as `<form {body}</form>` (invalid HTML) and lost
  action/method attrs entirely. Rewritten to use a single capture-group
  regex.
- `modules/external/osv_client.py::vuln_to_finding` parsed OSV's CVSS
  vector string (e.g. `CVSS:3.1/AV:N/...`) by `.split('/')[0]
  .replace('CVSS:','')` — which produces `"3.1"` (the spec version),
  NOT the base score. Now uses `database_specific.severity` (the
  authoritative qualitative label) and approximates a numeric only for
  sorting.
- `config/tool_paths.py::_version` ran `--version` against every tool,
  but gobuster v3+ uses the `version` subcommand and nikto uses
  `-Version`. Added per-tool overrides.
- `utils/http_client.py::head_status` claimed "HEAD-only" but actually
  did GET (with body sliced to 0 bytes). Rewritten to use a real HEAD
  request with a 405-fallback to GET.
- `core/scanner_engine.py` silent `except: pass` on checkpoint failures
  hid resume bugs — now logs.
- `core/session_manager.py::save_findings` silently swallowed DB insert
  failures — now logs the first failure with detail and a final count.
- `modules/web_scanner/gobuster_module.py::_load_words` silently fell
  back to built-in paths on wordlist read errors — now logs.
- Removed unused import in `modules/custom/surface_map.py` (head_status).

## [2.0.0] — 2026-06-07

### Added
- **Java/Swing GUI** (`gui/java/`) — JDK-only desktop findings console.
  Reads HunterPy JSON reports, no backend required, builds with a
  single `./build.sh` (no Maven/Gradle).
- **React/TypeScript frontend** (`gui/frontend/`) — Vite + Tailwind SPA
  for browser-based triage. Mock mode lets it run with no backend.
- **AI-consumable Markdown report** (`*.md`) — designed for paste into
  ChatGPT / Claude / Gemini for strategic guidance.
- **Behavioral baseline analyzer** — soft-404 detection, length / latency
  z-score anomaly scoring (no ML, just statistics).
- **Cross-finding attack-chain detector** (`classifiers/context_graph.py`)
  with 5 declarative chain rules.
- **PoC + impact analyzer** (`reporting/`) — per-finding verification
  steps + remediation + priority tiers (P1–P4) + compliance hints.
  Never emits working exploit payloads.
- **Nuclei integration** (severity-gated, opt-in).
- **OSV.dev JS package scanner** — replaces the fragile header-based
  CVE matching for JavaScript dependencies.
- **Google-dork generation** (`modules/osint/dork_builder.py`) —
  template-based, preview-only by default. Renders target-restricted
  Google URLs for manual review.
- **Hardened authorization prompt** — now requires typing the target
  hostname (typo-stop pattern). Bypass with `--i-am-authorized` for CI.
- **Interactive HTML report** with filter / sort / row expansion.
- **121 unit tests** across baseline, classifier, dedup, NVD client,
  OSV parser, dork builder, PoC generator, and validators.

### Changed
- **`tech_fingerprint`** now uses live NVD 2.0 API with SQLite caching
  + sliding-window rate limiting + offline fallback to bundled DB.
- **Surface map** (`modules/custom/surface_map.py`) replaces the old
  endpoint crawler — adds form / param / sensitive-path extraction.
- **Header analyzer** now also reports cookie security flags
  (HttpOnly / Secure / SameSite).
- **Report engine** restructured around `core/markdown_report.py` +
  `reporting/interactive_html.py`.

### Removed
- **`modules/hash_cracking/`** — auto-running `john` / `hashcat` in a
  web-scanner pipeline was never sensible. Removed entirely.
- **Active Google scraper** (`google_searcher.py`) — ToS violation +
  inevitable CAPTCHA blocks. Preview-mode dork generation replaces it.
- The old `--confirm-authorized` checkbox-only flow — replaced with the
  hostname-typing prompt.

### Security
- `TargetValidator` now strips schemes before checking and explicitly
  rejects loopback / RFC-1918 / `.gov` / `.mil`.
- `js_analyzer.py` masks any token-like string (20+ alphanumerics) in
  context snippets so real secrets are never written to disk.
- `dispatch_exports` no longer follows symlinks outside `output/`.

## [1.0.0] — 2026-06-06

Initial conversation-built release. Subprocess wrappers around nmap /
nikto / sqlmap / hydra / gobuster / ffuf, three-tier classifier, basic
JSON + HTML reports, NVD CVE matcher.
