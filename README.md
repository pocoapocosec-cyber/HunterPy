# HunterPy 🛡️

> Web-security recon orchestrator with a desktop console, a browser UI,
> a REST API, a Burp Suite bridge, and an AI-pasteable report format.

[![License: BUSL 1.1](https://img.shields.io/badge/license-BUSL%201.1-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](#requirements)
[![JDK](https://img.shields.io/badge/JDK-11%2B-blue.svg)](#requirements)
[![tests](https://img.shields.io/badge/tests-151%20passing-brightgreen.svg)](#testing)
[![Status](https://img.shields.io/badge/status-v2.1-orange.svg)](CHANGELOG.md)

---

## ⚠ Before you do anything else

HunterPy is for **authorized** security testing only. You may scan
systems you own, or systems for which you have **explicit written
permission** to test. The CLI refuses to scan:

- `localhost`, `127.0.0.0/8`, `::1`
- RFC-1918 ranges (`10/8`, `172.16/12`, `192.168/16`)
- `.gov`, `.mil` TLDs

And it requires you to **type the target hostname** at a confirmation
prompt before starting — a single checkbox isn't consent. See the
[Safety & ethics](#safety--ethics) section below for the full threat
model.

If you misuse this tool, that is on you, not the project.

---

## Table of contents

1. [What HunterPy is (and isn't)](#what-hunterpy-is-and-isnt)
2. [Architecture at a glance](#architecture-at-a-glance)
3. [Quick start](#quick-start)
   * [Python CLI](#1-python-cli)
   * [REST API + React frontend](#2-rest-api--react-frontend)
   * [Desktop GUI (Java/Swing)](#3-desktop-gui-javaswing)
   * [Docker (bundled tools)](#4-docker-bundled-tools)
   * [Burp Suite](#5-burp-suite)
4. [Scan modes](#scan-modes)
5. [Modules reference](#modules-reference)
6. [The classifier](#the-classifier)
7. [Reports](#reports)
8. [Verification (safe exploit confirmation)](#verification-safe-exploit-confirmation)
9. [User-Agent rotation](#user-agent-rotation)
10. [CLI reference](#cli-reference)
11. [REST API reference](#rest-api-reference)
12. [Configuration & environment](#configuration--environment)
13. [Testing](#testing)
14. [Safety & ethics](#safety--ethics)
15. [Honest comparison](#honest-comparison)
16. [Roadmap & limitations](#roadmap--limitations)
17. [License](#license)

---

## What HunterPy is (and isn't)

**HunterPy is:**

- A **Python orchestrator** (`ScannerEngine`) that runs ~18 modules
  spanning passive recon, active scanning, exploitation testing, and
  authentication testing.
- A **three-tier classifier** (`FindingClassifier`) that sorts findings
  into 🔴 INTERESTING / 🟡 COMMON / 🟢 FALSE_ALARM using pattern packs,
  numeric scoring, behavioral baselines, and cross-finding context rules.
- A **report engine** producing JSON, interactive HTML, plain-text,
  AI-consumable Markdown, **and Burp Suite issue-import XML**.
- A **REST API** (FastAPI) exposing 25+ endpoints for scan
  orchestration, findings retrieval, and report generation.
- A **React + TypeScript web UI** that talks to the API or works
  standalone against bundled mock data.
- A **Java/Swing desktop GUI** (zero third-party deps) that loads
  JSON reports for offline triage — ships as a single JAR.
- A **Burp Suite extension** that brings HunterPy findings into Burp's
  Site Map, Issues view, and Repeater.

**HunterPy is not:**

- Burp Suite. We don't proxy live traffic or modify requests in flight.
- Nessus. We don't ship 200,000 hand-crafted vulnerability signatures.
- A Google scraper. We render dork *suggestions* you open in a browser;
  we never hit `google.com` automatically.
- A hash cracker. Auto-chaining `john`/`hashcat` into a web scan was
  always a bad idea — removed in v2.0.

**Honest commercial positioning:** HunterPy is best used as a **triage
layer** *in front of* Burp / Nuclei / a human pentester. Run it first to
get a prioritised attack-surface map; let the experts deep-dive what it
surfaces.

---

## Architecture at a glance

```
                        ┌────────────────────┐
   CLI ──────────────►  │   ScannerEngine    │  ◄── REST API (FastAPI)
   (main.py)            │  (5-phase pipeline)│      (gui/backend/)
                        └─────────┬──────────┘             │
                                  │                        │
            ┌─────────────────────┼─────────────────────┐  │
            │                     │                     │  │
            ▼                     ▼                     ▼  │
   ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
   │   18 modules   │   │  Classifier +  │   │  Report engine │
   │ recon / active │   │  context graph │   │  (5 formats)   │
   └────────┬───────┘   └────────────────┘   └───────┬────────┘
            │                                        │
            ▼                                        ▼
       SQLite DB                              output/*.{json,html,md,burp.xml,txt}
                                                     │
                ┌─────────────────────────────────────┼──────────────────────┐
                ▼                                     ▼                      ▼
       ┌────────────────┐                  ┌────────────────┐    ┌──────────────────┐
       │  React web UI  │                  │  Java Swing    │    │   Burp Suite     │
       │  gui/frontend  │                  │  desktop GUI   │    │   extension OR   │
       │  (via REST)    │                  │  gui/java      │    │   XML import     │
       └────────────────┘                  └────────────────┘    └──────────────────┘
```

Directory layout:

```
HunterPy/
├── main.py                       Python CLI entry point
├── core/
│   ├── scanner_engine.py         5-phase ScannerEngine
│   ├── target_validator.py       Safety + scope checks (loopback / RFC-1918 / .gov)
│   ├── session_manager.py        scan_id, checkpointing, DB writes
│   ├── markdown_report.py        AI-consumable Markdown renderer
│   └── report_engine.py          Dispatcher → JSON / HTML / TXT / MD / Burp XML
├── modules/
│   ├── custom/                   headers, ssl, dns, whois, surface, js, tech, cors
│   ├── web_scanner/              nikto, gobuster, ffuf, wfuzz wrappers
│   ├── injection/                sqlmap wrapper (safe defaults)
│   ├── auth_testing/             hydra wrapper (small built-in lists only)
│   ├── external/                 nuclei (opt-in), OSV.dev JS package scanner
│   ├── intelligence/             baseline_analyzer (statistical, not ML)
│   └── osint/                    dork_builder + module (preview-only by default)
├── classifiers/
│   ├── finding_classifier.py     Three-tier classification
│   ├── severity_scorer.py        Numeric 0-10 score
│   ├── dedup_engine.py           Cross-module deduplication
│   └── context_graph.py          Attack-chain detection
├── reporting/
│   ├── poc_generator.py          Per-type PoC + remediation builders
│   ├── impact_analyzer.py        P1-P4 priority / SLA / compliance hints
│   ├── interactive_html.py       Single-file interactive HTML report
│   └── burp_exporter.py          Burp Suite XML issue-import format
├── utils/
│   ├── http_client.py            Shared HTTP wrapper (requests + urllib fallback)
│   ├── database.py               SQLite (scans, findings, NVD cache, checkpoints)
│   ├── validators.py             Base IP/domain validation
│   ├── output_parser.py          nmap / nikto line parsers
│   ├── process_runner.py         Subprocess timeout + cleanup
│   ├── rate_limiter.py           Sliding-window limiter
│   └── logger.py                 ScanLogger (per-scan log + command audit)
├── signatures/                   6 JSON rule packs (FPs, dorks, CVEs, WAFs)
├── samples/                      sample_scan.json bundled for GUI demos
├── tests/                        130 unit tests (Python core)
├── gui/
│   ├── backend/                  FastAPI REST API (21 tests)
│   │   ├── app.py
│   │   ├── routes/{scans,findings,reports,misc}.py
│   │   ├── services/{scan_manager,report_reader}.py
│   │   └── tests/test_api.py
│   ├── frontend/                 React + Vite + TypeScript + Tailwind
│   ├── java/                     Swing desktop GUI + headless SmokeTest
│   └── burp-extension/           Montoya-API Burp extension
├── Dockerfile                    Multi-stage build with all scanners bundled
├── docker-compose.yml
├── LICENSE                       Business Source License 1.1
├── SECURITY.md                   Threat model + disclosure policy
└── CHANGELOG.md
```

---

## Quick start

### 1. Python CLI

Prereqs: **Python 3.10+**, optional external tools (`nmap`, `nikto`,
`sqlmap`, `hydra`, `gobuster`, `ffuf`, `nuclei` — install whichever you
have). HunterPy gracefully falls back to its own pure-Python probes when
a tool is missing.

```bash
pip install -r requirements.txt

# See what's missing on your machine
python main.py --check-tools

# Plan an install (DRY-RUN — prints the commands, runs nothing).
# Pinned versions live in config/tool_installer.py.
python main.py --install-tools

# Actually execute the plan. Apt/brew steps need sudo — run `sudo -v`
# in this terminal first; the installer never prompts for a password.
python main.py --install-tools --install-tools-confirm

# Just install one or two:
python main.py --install-tools --install-tools-only sqlmap wfuzz \
    --install-tools-confirm

# A `tools.lock.json` is written every run — diff it across CI runs.
# Go-toolchain tools (nuclei) are NEVER auto-installed — the installer
# prints the `go install ...@<pinned-tag>` command for you to run.

# Strictly passive — safe for any authorized target
python main.py -t example.com --mode passive --confirm-authorized

# At the prompt, type the target hostname to confirm:
#   Type the target hostname to confirm authorized scanning
#   (example.com) or CTRL+C:
#   > example.com

# Skip the prompt for CI / automation only:
python main.py -t example.com --mode passive \
    --confirm-authorized --i-am-authorized

# Full scan (runs everything that's installed) with NVD CVE lookups:
NVD_API_KEY=$YOUR_KEY python main.py -t example.com --mode full \
    --confirm-authorized --i-am-authorized
```

Output lands in `./output/<target>_<timestamp>.{json,html,md,burp.xml,txt}`.

### 2. REST API + React frontend

The backend wraps `ScannerEngine` in a thread-per-scan manager and
exposes a 25-endpoint REST surface. The React UI then becomes a real
operational console instead of mock-data demo.

```bash
# Terminal 1 — start the API
pip install fastapi 'uvicorn[standard]' httpx python-multipart
python -m gui.backend.app
# → http://127.0.0.1:8000   (API)
# → http://127.0.0.1:8000/docs   (OpenAPI / Swagger)

# Terminal 2 — start the frontend in real-API mode
cd gui/frontend
echo "VITE_USE_MOCKS=false" > .env.local
echo "VITE_API_BASE_URL=http://127.0.0.1:8000" >> .env.local
npm install
npm run dev
# → http://127.0.0.1:5173
```

Backend env vars:

| Variable                 | Default                                      | Purpose                                |
|--------------------------|----------------------------------------------|----------------------------------------|
| `HUNTERPY_HOST`          | `127.0.0.1`                                  | uvicorn bind address                   |
| `HUNTERPY_PORT`          | `8000`                                       | uvicorn bind port                      |
| `HUNTERPY_CORS_ORIGINS`  | `http://localhost:5173,http://127.0.0.1:5173`| Comma-separated allowed origins        |

If you put the API on a network reachable beyond `localhost`, **put a
reverse proxy with auth in front of it.** The bundled `/api/auth/login`
endpoint is a stub.

### 3. Desktop GUI (Java/Swing)

Zero third-party Java deps. One `./build.sh` produces an executable
JAR.

```bash
cd gui/java
./build.sh           # → out/ (.class files) and HunterPyGUI.jar
java -cp out io.hunterpy.gui.App ../../output/example.com_*.json

# Or, if `jar` is on PATH:
java -jar HunterPyGUI.jar ../../output/example.com_*.json
```

Requires **JDK 11+**. Tabs: **Overview** (donut charts + attack chains)
· **Findings** (sortable / filterable table → click for PoC) · **Target**
(DNS / WHOIS / baseline) · **Dorks** (clickable Google URLs).

See [`gui/java/README.md`](gui/java/README.md) for architecture notes.

### 4. Docker (bundled tools)

```bash
docker build -t hunterpy:2.1 .

# Run a scan, mount output/ on the host so files persist
mkdir -p output && export UID GID
docker run --rm -v "$PWD/output:/work/output" hunterpy:2.1 \
    -t example.com --mode passive --confirm-authorized --i-am-authorized

# Drop into a shell with every scanner already on PATH
docker run --rm -it --entrypoint bash hunterpy:2.1
```

Or use the bundled `docker-compose.yml`:

```bash
docker compose run --rm hunterpy -t example.com --mode passive \
    --confirm-authorized --i-am-authorized --no-nvd

# All-tools shell:
docker compose run --rm shell
```

The image is non-root (`uid:gid 1000:1000`), built on
`python:3.12-slim-bookworm`. `nuclei` is built from source (pinned to
`v3.2.9`); everything else (`nmap`, `nikto`, `sqlmap`, `hydra`,
`gobuster`, `ffuf`) comes from Debian's standard repos. `tini` runs as
PID 1 so Ctrl-C reaches the Python process cleanly.

### 5. Burp Suite

Two paths — pick whichever you trust more:

**Zero-install XML import:**

```bash
python main.py -t example.com --confirm-authorized --i-am-authorized \
    --mode passive --no-nvd --format burp
# → output/example.com_*.burp.xml
```

In Burp: **Project options ▸ Misc ▸ Issue import** → pick the file.
Works on Burp **Pro and Community**.

**Native Java extension** (`gui/burp-extension/`):

```bash
cd gui/burp-extension
# 1. Drop montoya-api-<version>.jar into lib/  (download from Burp ▸ APIs)
# 2. ./build.sh   → hunterpy-burp.jar
# 3. Burp ▸ Extensions ▸ Add ▸ Java ▸ select hunterpy-burp.jar
```

The extension adds a HunterPy tab inside Burp that loads JSON reports,
sends URLs to Repeater, and emits findings into the Site Map's Issues
view. See [`gui/burp-extension/README.md`](gui/burp-extension/README.md).

---

## Scan modes

| Mode          | Threads | Rate (req/s) | Default modules                                                                |
|---------------|--------:|-------------:|--------------------------------------------------------------------------------|
| `passive`     | 5       | 5            | fingerprint, headers, ssl, dns, whois, surface, js, js_vulns, dorks, endpoints |
| `quick`       | 5       | 5            | headers, ssl, fingerprint, gobuster, nikto, symfony                            |
| `standard`    | 10      | 10           | quick + endpoints, ffuf, cors, sqlmap, default_creds                           |
| `full`        | 20      | 20           | standard + wfuzz, nuclei, hydra (every tool you have)                          |
| `stealth`     | 2       | 1            | passive + nikto + gobuster + default_creds, 2s delay                           |
| `strict`      | 20      | 20           | same modules as `full` — but **fails-fast** at scan start if any required external tool is missing |
| `best-effort` | 10      | 10           | same modules as `standard` — explicitly accepts Python fallbacks for missing tools |
| `custom`      | as set  | as set       | exactly what you pass via `--modules`                                          |

Mode determines threads, rate-limit, and the default module set. You can
always override modules explicitly:

```bash
python main.py -t example.com --confirm-authorized --i-am-authorized \
    --modules headers ssl dns surface js
```

### Module-coverage transparency (v2.6+)

Every scan now prints a coverage banner at start **and** end. Each
selected module is tagged with one of four tiers:

| Tier        | Meaning                                                                       |
|-------------|--------------------------------------------------------------------------------|
| `full` (✓)  | External tool is present and was executed                                    |
| `fallback` (⚠) | Tool missing but a (degraded) Python fallback ran                          |
| `skipped` (✗)  | Tool missing AND no fallback exists — module produced nothing             |
| `native` (·)   | Pure-Python module, no external dependency                                |

`--mode strict` refuses to start if any module is below `full`. Use it
for engagements where "scan ran but actually skipped half the modules"
would be a worse outcome than "scan didn't start, fix your tools."
`--mode best-effort` explicitly accepts fallbacks (banner still prints).

---

## Modules reference

All 18 modules registered in `ScannerEngine.MODULE_MAP`:

### Passive recon (Phase 1 — runs in parallel, safe for any target)

| Module        | What it does                                                       |
|---------------|--------------------------------------------------------------------|
| `fingerprint` | Tech stack from `Server`/`X-Powered-By`/body sigs; OSV+NVD lookup  |
| `headers`     | Security-header audit + cookie flags (HttpOnly/Secure/SameSite)    |
| `ssl`         | TLS handshake, cert expiry, weak ciphers, weak key size, weak proto|
| `dns`         | A / AAAA / MX / NS / TXT / CNAME via dnspython (stdlib fallback)   |
| `whois`       | Registrar, dates, status (via `python-whois` if installed)         |
| `surface`     | Link / subdomain / form / param / sensitive-path extraction        |
| `js`          | Concurrent JS download, keyword scan (api_key, token, …) — masked  |
| `js_vulns`    | OSV.dev JS-package vulnerability lookup                            |
| `endpoints`   | Lightweight crawler feeding endpoints into later modules           |
| `dorks`       | Google-dork generation (preview-only — no scraping)                |
| `symfony`     | Symfony exposure intel pack — Profiler / app_dev.php / LFI / APP_ENV injection (see [docs/threat-intel/](docs/threat-intel/)) |

#### About the Symfony intel pack

`signatures/intel/symfony_exposure.json` is a structured distillation
of three real-world pentest reports (preserved under
`docs/threat-intel/SECREP-*.pdf`). The `symfony` module probes the
exposure paths from that file, fingerprints Symfony from headers /
body markers, and scans the landing page for credential-leak patterns
(values are always redacted before being written).

Detected types feed into:
- Three-tier classifier (every Symfony finding is INTERESTING)
- Context graph chains: `symfony_full_pwnage`,
  `symfony_dev_mode_in_prod`, `imagemagick_upload_rce_recipe`
- Per-type PoC builders that cite the originating SECREP report
- Impact analyzer (priority tier + compliance hints)
- Markdown report → AI-pasteable triage section
- Burp Suite XML export

### Active scanning (Phase 2 — requires external tools)

| Module     | External tool | Falls back to                              |
|------------|---------------|---------------------------------------------|
| `nikto`    | `nikto`       | Built-in HEAD checks against 8 high-value paths |
| `gobuster` | `gobuster`    | Built-in 50-path probe with rate-limiting   |
| `ffuf`     | `ffuf`        | Skips (logs `skipped`)                      |
| `wfuzz`    | `wfuzz`       | Skips                                       |
| `nuclei`   | `nuclei`      | Skips                                       |

### Exploitation testing (Phase 3)

| Module   | External tool | Notes                                            |
|----------|---------------|--------------------------------------------------|
| `sqlmap` | `sqlmap`      | `--level 1 --risk 1` defaults (non-destructive)  |
| `cors`   | (built-in)    | Tests for wildcard / reflection / null-origin    |

### Authentication testing (Phase 4)

| Module          | External tool | Notes                                                                                                          |
|-----------------|---------------|-----------------------------------------------------------------------------------------------------------------|
| `default_creds` | (built-in)    | Single-shot audit of 20 documented default pairs (admin/admin, root/root, …). Stops at first hit. Always on.    |
| `hydra`         | `hydra`       | Web-form brute-force. **Off by default** in v2.6+; pass `--enable-bruteforce` to run. Tiny built-in cred list. |

The `default_creds` module is the recommended path for "is admin/admin
still valid?" — the answer pentest customers actually want. Hydra is
loud, slow, ineffective on modern apps with lockout policies, and
commonly out of SOW for web targets; we made it opt-in.

---

## The classifier

Every finding is classified as **🔴 INTERESTING / 🟡 COMMON / 🟢 FALSE_ALARM**
through these stages, in order:

1. **Module hints** — `confirmed=True`, `interesting=True`,
   `likely_false_alarm=True` flags from the producing module
2. **Type maps** — explicit allow-lists in
   `classifiers/finding_classifier.py`:
   - `FALSE_ALARM_TYPES` (e.g. `x_xss_protection_missing`, `robots_txt`)
   - `INTERESTING_TYPES` (e.g. `git_exposed`, `env_exposed`, `sql_injection`)
   - `COMMON_TYPES` (e.g. `missing_security_header`)
3. **Signature packs** — JSON patterns under `signatures/`
   (`common_fps.json`, `interesting_patterns.json`)
4. **Numeric severity score** (`SeverityScorer`) — combines base
   severity, type boost, path heuristics, CVSS
5. **Context rules** (`ContextGraph`) — fires synthetic findings for
   declarative attack chains:
   - dev subdomain + exposed `.git/HEAD` → escalate
   - outdated component + open admin path → escalate
   - weak CSP + login form on same page → escalate
   - permissive CORS + weak cookies → escalate
   - SQL injection + admin path → escalate

The classifier never modifies the original finding's `severity` field —
it adds `classification`, `classification_confidence`, and
`classification_reason` so the chain of reasoning is auditable.

### Explainability (`classification_explanation`, v2.6+)

Alongside the one-line `classification_reason` string, every finding
now carries a structured `classification_explanation` block. This is
what client reports, FP-feedback loops, and SOC2/ISO27001 auditors
actually need:

```json
{
  "final_class": "INTERESTING",
  "confidence": 0.85,
  "primary_reason": "module confirmed the finding",
  "factors": [
    {"kind": "module_hint",    "field": "confirmed",  "weight": 1.0},
    {"kind": "type_table",     "table": "INTERESTING_TYPES",
     "value": "symfony_profiler_phpinfo", "weight": 0.8},
    {"kind": "signature_pack", "pack": "interesting_patterns.json",
     "matched_entry": {"id": "...", "contains": "...", "regex": null,
                        "module": null}, "weight": 0.8},
    {"kind": "context_rule",   "rule": "vuln_server_banner",
     "matched_substring": "php/5", "weight": 0.6},
    {"kind": "severity_score", "score": 7.5, "weight": 0.75}
  ],
  "context_chains": ["symfony_full_pwnage"],
  "human_explanation": "Classified as INTERESTING (module confirmed
   the finding). Primary signal: the producing module asserted
   `confirmed` on the finding. Participates in attack chain(s):
   symfony_full_pwnage."
}
```

Every factor `kind` has a stable schema so tooling can aggregate
("how many findings were promoted by `vuln_server_banner` last
month?"). The `human_explanation` is what goes into client-facing
report templates.

---

## Reports

`--format` accepts: `txt`, `json`, `html`, `md` / `markdown`, `burp`,
`all` (default).

| Format     | Best for                                                |
|------------|----------------------------------------------------------|
| `json`     | Programmatic consumption, REST API, GUI loaders          |
| `html`     | Self-contained interactive report — filter, sort, expand |
| `md`       | Paste into ChatGPT / Claude / Gemini for triage guidance |
| `txt`      | Quick terminal review, CI logs                           |
| `burp`     | Burp Suite issue-import XML                              |
| `all`      | Every format above                                       |

The **Markdown** report is structured so an LLM can answer:

> "Rank these findings by exploitability. What manual tests should I run
> next? Identify any chained / multi-step attacks suggested by this scan."

Sections appear in stable order: Legal · How To Use · Scan Metadata ·
Tech Stack · Header Audit · Cookies · DNS · WHOIS · Links · Forms · URL
Parameters · Sensitive Paths · JS Analysis · **Google Dorks (for manual
review)** · Verification Results · Notable Findings · Next Steps.

### YAML frontmatter (v2.6+)

The markdown report opens with a YAML frontmatter block — LLMs parse
it cleanly, humans skip it, CI pipelines can `grep` it for summary
counts without parsing the whole report:

```yaml
---
scan_id: 'acme-2026-Q2-001'
target: 'acme.example.com'
mode: 'standard'
generated_at: '2026-06-07T12:00:00Z'
tool: 'HunterPy'
tool_version: '2.6.0'
findings_summary:
  total: 24
  critical: 2
  high: 5
  medium: 12
  low: 5
  by_class:
    interesting: 7
    common: 12
    false_alarm: 5
attack_chains:
  - type: 'chain_symfony_full_pwnage'
    severity: 'CRITICAL'
    steps:
      - 'profiler_exposed'
      - 'leaked_db_creds'
      - 'admin_panel'
verification_summary:
  total: 7
  confirmed: 5
  inconclusive: 2
---
```

### HTML report Content-Security-Policy (v2.6+)

The single-file interactive HTML report ships with a strict CSP meta
tag: `default-src 'none'`, `script-src 'sha256-<hash-of-inline-script>'`
(no `'unsafe-inline'`), and `connect-src`/`form-action`/`base-uri`/
`frame-ancestors` all locked to `'none'`. Opening the report from an
attacker-controlled directory cannot hijack its inline JS.

If you fork the report template and edit the inline script, you must
re-emit through `render_interactive_html()` — the SHA-256 is computed
at render time, so a hand-edited HTML file with stale CSP will refuse
to execute its own script (loud failure, not silent corruption).

---

## Verification (safe exploit confirmation)

HunterPy v2.3 adds **Phase 6**, an opt-in verification subsystem that
takes findings the scanner already detected and runs the *least-invasive
request that proves exploitability*. It is **not** an exploitation
framework — it does not drop webshells, persist code, brute-force
credentials, or pivot. For weaponisation use a real C2 framework
(Sliver, Mythic, Cobalt Strike) under explicit engagement terms.

Read [`docs/VERIFICATION.md`](docs/VERIFICATION.md) end-to-end before
enabling on a live target. The short version:

```bash
# 1. Issue a signed authorization file (one-time per engagement).
#    The HMAC key auto-generates at ~/.hunterpy/auth.key (mode 0600).
python main.py --verify-issue-auth ./engagement-acme.auth.json \
    --verify-engagement "Acme/2026Q2/SOW-471" \
    --verify-operator "you@yourfirm.example" \
    --verify-hostnames acme.example.com '*.staging.acme.example.com' \
    --verify-valid-days 14 \
    --verify-max-safety trivial_write

# 2. Run a scan with --verify. The verifier will prompt y/n per finding
#    after classification, only for INTERESTING / CRITICAL / HIGH ones
#    that have a registered probe.
python main.py -t acme.example.com --mode standard \
    --confirm-authorized \
    --verify --verify-auth-file ./engagement-acme.auth.json

# 3. CI / unattended mode (auth file still enforces scope + expiry):
python main.py -t acme.example.com --mode passive \
    --confirm-authorized --i-am-authorized \
    --verify --verify-auth-file ./engagement-acme.auth.json \
    --verify-non-interactive --verify-rate-limit 0.2
```

Every verification attempt writes a self-contained evidence bundle to
`<output>/verification/<finding_uid>/` containing the full
request/response transcript (with secrets redacted to SHA-256
fingerprints), the active authorization, the probe result, and a short
`proof.txt`. Hand it to the client along with the report.

What ships out of the box (more in `docs/VERIFICATION.md`):

| Finding type                       | Probe behaviour                                                            |
|------------------------------------|----------------------------------------------------------------------------|
| `symfony_profiler_exposed`         | GET `/_profiler/`, check for toolbar markup + tokens                       |
| `symfony_profiler_phpinfo`         | GET `/_profiler/phpinfo`, hash leaked env-var values                       |
| `symfony_profiler_lfi`             | Read `/etc/hostname` via `open?file=` (boring, sufficient proof)           |
| `symfony_app_env_injection`        | Send `?+--env=dev`, diff vs baseline (CVE-2024-50340)                      |
| `symfony_exposed_credentials`      | Re-fetch URL, confirm pattern still triggers                               |
| `git_exposed`                      | GET `.git/HEAD`, confirm valid git ref                                      |
| `env_exposed`                      | GET URL, confirm dotenv format                                              |
| `admin_panel`                      | GET URL, confirm login UI (never submits credentials)                       |
| `source_map_exposed`               | GET URL, confirm v3 source-map JSON                                         |
| `unrestricted_file_upload`         | Upload **plain `.txt`** marker, GET back, attempt DELETE                    |

### Manual PoC writer (`--write-poc`, v2.6+)

Pass `--write-poc` alongside `--verify` and every CONFIRMED finding
gets three additional files in its evidence bundle:

```
verification/<finding_uid>/
├── poc.sh    # single-curl reproducer, mode 0700
├── poc.py    # stdlib-only urllib reproducer, mode 0700
└── poc.md    # README explaining usage, safety, cleanup
```

Both scripts exit **`0`** if the issue is **still reproducible** (the
fix is NOT in place) and **`1`** if the response diverged (the fix
**may** be working). Drop them into the client's CI pipeline as
regression checks after they ship a fix.

These PoCs are explicitly NOT exploits:

- single request (no loops, no retries, no fuzzing)
- no shell drops, persistence, or pivoting
- no modification of target state beyond what the verifier already
  sent
- carry the engagement's authorization context + the
  `X-HunterPy-Verify` consent UUID so the blue team can correlate

If you need post-exploitation tooling, that lives in a separate
operator-driven workflow under your engagement SOW — Sliver, Mythic,
Cobalt Strike. HunterPy is the recon + verification + reproducer
layer, deliberately not the weaponisation layer.

---

## User-Agent rotation

By default every HunterPy request identifies itself as
`HunterPy/2.0 (+authorized-testing)`. That's deliberate — many SOWs
*require* scanner traffic to be identifiable in target logs, and an
honest UA is what makes the tool defensible. Override only when there's
a concrete reason:

| Reason                                | What rotation helps you find                                                  |
|---------------------------------------|--------------------------------------------------------------------------------|
| **WAF testing**                       | Does the WAF block `HunterPy` but pass `Chrome/124`? That's a finding.        |
| **UA-conditional rendering**          | Does the app serve a different SPA bundle to iOS Safari vs desktop Chrome?    |
| **Bot-detection evaluation**          | Which UAs does the bot-management product trust vs challenge vs block?         |
| **Cache-key probing**                 | Does the CDN serve different cached content based on the UA?                  |

### CLI

```bash
# See every preset (chrome-windows, firefox-linux, safari-ios, etc.)
python main.py --list-user-agents

# Single override (backwards-compat with v2.4 and earlier)
python main.py -t example.com --confirm-authorized \
    --user-agent "Mozilla/5.0 (...)"

# Use a built-in preset
python main.py -t example.com --confirm-authorized \
    --user-agent-preset chrome-windows

# Rotate across a multi-UA preset, picking randomly per request
python main.py -t example.com --confirm-authorized \
    --user-agent-preset desktop-browsers \
    --user-agent-strategy rotate-random

# Bring your own pool from a file (one UA per line, `#` comments OK)
python main.py -t example.com --confirm-authorized \
    --user-agent-file ./my-uas.txt \
    --user-agent-strategy rotate-sequential

# Explicit inline pool
python main.py -t example.com --confirm-authorized \
    --user-agent-pool "Mozilla/5.0 (...)" "curl/8.8.0" \
    --user-agent-strategy rotate-sequential
```

### Strategies

| Strategy             | Behaviour                                                                    |
|----------------------|-------------------------------------------------------------------------------|
| `static` (default)   | One UA for the whole scan (the first entry in the pool).                     |
| `rotate-random`      | Pick uniformly at random per request.                                        |
| `rotate-sequential`  | Thread-safe round-robin through the pool per request.                        |

Rotation requested on a pool of size 1 silently collapses to `static`
with a warning — otherwise it would be a confusing no-op.

### Precedence (highest wins)

1. `--user-agent-pool "A" "B" ...`
2. `--user-agent-file PATH`
3. `--user-agent-preset NAME`
4. `--user-agent STRING`
5. The hard-coded default.

### Preset categories

| Category                | Examples                                       | Notes                                         |
|-------------------------|------------------------------------------------|------------------------------------------------|
| `tool`                  | `default`, `curl`, `wget`                      | Honest disclosure; useful for WAF testing.    |
| `browser`               | `chrome-windows`, `firefox-linux`, `safari-ios`, `desktop-browsers`, `all-browsers` | The common case.                              |
| `noisy_impersonation`   | `googlebot`, `bingbot`                         | Spoofing search-engine bots can violate ToS and is blocked by mature WAFs via IP-pinning. Use only when explicitly testing for cloaking / bot-allowlist misconfigurations. |

### Where rotation is and isn't applied

| Component                                       | Behaviour                                                       |
|-------------------------------------------------|------------------------------------------------------------------|
| `endpoint_crawler`, `surface_map`, `symfony_detector` | Per-request rotation when strategy ≠ `static`.            |
| `baseline_analyzer`                             | **Always static** — consistent UA across baseline + test is what makes the comparison meaningful. |
| Verification probes (`modules/exploit/probes/*`) | Honour the configured UA, but always append `verify/<consent_marker>` to the UA string so the `X-HunterPy-Verify` blue-team correlation marker survives rotation. |
| External binaries (nikto/gobuster/etc.)         | Receive the configured *primary* UA via their own `--user-agent` flag — they don't rotate per request. |

### REST API

```bash
# Catalogue endpoint, used by the frontend dropdown
curl http://127.0.0.1:8000/api/user-agents
# → {"default": "...", "strategies": [...], "presets": [...]}

# Pass UA options through the standard scan-create payload
curl -X POST http://127.0.0.1:8000/api/scans \
    -H 'Content-Type: application/json' \
    -d '{
        "target": "example.com",
        "mode":   "passive",
        "modules": ["headers", "ssl", "symfony"],
        "options": {
            "user_agent_preset":   "desktop-browsers",
            "user_agent_strategy": "rotate-random"
        }
    }'
```

---

## CLI reference

```
python main.py [-h] [-t TARGET] [-tL TARGET_LIST] [--scope SCOPE]
    [--mode {passive,quick,standard,full,stealth,custom}]
    [--modules {nikto,sqlmap,gobuster,ffuf,wfuzz,hydra,nuclei,
                headers,cors,ssl,fingerprint,endpoints,dns,whois,
                surface,js,js_vulns,dorks} ...]
    [--auth-url AUTH_URL] [--username USERNAME]
    [--username-list FILE] [--password-list FILE]
    [-o OUTPUT] [--format {txt,json,html,md,markdown,burp,all}]
    [-v] [--no-color]
    [--confirm-authorized] [--i-am-authorized]
    [--rate-limit N] [--delay SECONDS]
    [--threads N] [--timeout SECONDS]
    [--proxy URL] [--user-agent UA] [--cookies STR]
    [--headers KEY:VALUE [KEY:VALUE ...]]
    [--no-nvd] [--nvd-offline] [--nvd-api-key KEY]
    [--dork-templates NAME ...] [--dork-extra KEYWORDS]
    [--dorks-active] [--confirm-dork-scraping]
    [--dork-max-queries N] [--dork-max-results N]
    [--list-dork-templates] [--list-scans] [--clear-nvd-cache]
    [--check-tools]
```

Highlights:

| Flag                        | What it does                                                |
|-----------------------------|-------------------------------------------------------------|
| `--confirm-authorized`      | **Required** — first half of the two-step authorization     |
| `--i-am-authorized`         | Skip the interactive hostname-typing prompt (CI only)       |
| `--mode passive`            | Strictly non-intrusive; safe for any authorized target      |
| `--format burp`             | Burp Suite issue-import XML                                 |
| `--no-nvd` / `--nvd-offline`| Disable / cache-only NVD CVE lookups                        |
| `--dorks-active`            | Actually scrape Google (requires `--confirm-dork-scraping`) |
| `--check-tools`             | Print every scanner's availability + version, then exit     |
| `--list-dork-templates`     | Print the 11 dork templates and exit                        |

Full CLI help: `python main.py --help`.

---

## REST API reference

Mounted under `/api/`. OpenAPI/Swagger UI at `/docs`.

| Method | Path                                       | Notes                                          |
|--------|--------------------------------------------|------------------------------------------------|
| GET    | `/api/scans`                               | list scans (`?status=running&limit=N&offset=N`)|
| POST   | `/api/scans`                               | create a scan (validates target server-side)   |
| GET    | `/api/scans/validate-target?target=…`      | dry-run target validation                      |
| POST   | `/api/scans/validate-target`               | same, body form                                |
| GET    | `/api/scans/{id}`                          | fetch one scan                                 |
| DELETE | `/api/scans/{id}`                          | cancel + delete                                |
| POST   | `/api/scans/{id}/start`                    | begin scan in a background thread              |
| POST   | `/api/scans/{id}/pause`                    | no-op (logged) — engine is synchronous         |
| POST   | `/api/scans/{id}/resume`                   | alias of start                                 |
| POST   | `/api/scans/{id}/cancel`                   | request graceful cancellation                  |
| GET    | `/api/scans/{id}/progress`                 | live progress                                  |
| GET    | `/api/scans/{id}/logs`                     | tail the per-scan ring buffer                  |
| GET    | `/api/scans/{id}/modules`                  | per-module status                              |
| GET    | `/api/scans/{id}/findings`                 | findings from the latest report on disk        |
| GET    | `/api/scans/{id}/target`                   | tech / DNS / WHOIS surface                     |
| GET    | `/api/scans/{id}/report`                   | full JSON report                               |
| GET    | `/api/scans/{id}/findings/export?format=json|csv` | streaming file download                |
| GET    | `/api/findings`                            | findings across all scans                      |
| GET    | `/api/findings/{id}`                       | single finding                                 |
| POST   | `/api/findings/{id}/exploit`               | **501** — disabled by design                    |
| POST   | `/api/findings/{id}/tags`                  | tag (client-side persistence in v2.1)          |
| GET    | `/api/reports`                             | list on-disk reports                           |
| GET    | `/api/reports/templates`                   | report-format options                          |
| GET    | `/api/reports/{id}`                        | one report by filename                         |
| GET    | `/api/tools`                               | external-tool availability check               |
| GET    | `/api/settings`                            | UI defaults (in-memory)                        |
| PUT    | `/api/settings`                            | update UI defaults                             |
| POST   | `/api/auth/login`                          | **stub** — any non-empty creds work            |
| GET    | `/api/auth/me`                             | stub current-user                              |

---

## Configuration & environment

### Environment variables

| Variable                | Default                                       | Purpose                              |
|-------------------------|-----------------------------------------------|--------------------------------------|
| `NVD_API_KEY`           | _(none)_                                      | 10× higher NVD CVE rate limit        |
| `HUNTERPY_HOST`         | `127.0.0.1`                                   | API bind host                        |
| `HUNTERPY_PORT`         | `8000`                                        | API bind port                        |
| `HUNTERPY_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated CORS allow-list      |
| `HUNTERPY_IN_DOCKER`    | _(set inside the image)_                      | Cosmetic; modules check it to skip… |

### Signature packs

All under `signatures/` — JSON, no code changes to extend:

| File                          | Purpose                                            |
|-------------------------------|----------------------------------------------------|
| `common_fps.json`             | Patterns the classifier should treat as false positives |
| `interesting_patterns.json`   | Patterns that should always be INTERESTING         |
| `vulnerability_db.json`       | Bundled offline CVE DB (NVD fallback)              |
| `waf_signatures.json`         | WAF / CDN fingerprints                             |
| `normalization_rules.json`    | Scoring weights & lookup tables                    |
| `dork_templates.json`         | 11 Google-dork templates, `{target}`-templated     |

---

## Testing

Three independent test suites cover the three runtimes:

```bash
# 1. Python core — 130 tests
python -m unittest discover -s tests

# 2. FastAPI backend — 21 tests (uses fastapi.testclient, no real network)
python -m unittest discover -s gui/backend/tests

# 3. Java GUI — 16 headless smoke assertions
cd gui/java && ./build.sh

# 4. TypeScript frontend — type-check + production build
cd gui/frontend && npx tsc --noEmit && npx vite build

# 5. Burp extension — compile against stubbed Montoya API
cd gui/burp-extension && ./build.sh   # needs lib/montoya-api.jar
```

What the **130 core tests** cover:

| File                            | Tests of                                       |
|---------------------------------|------------------------------------------------|
| `test_baseline.py`              | Behavioral baseline soft-404 / z-score        |
| `test_burp_exporter.py`         | Burp XML validity, severity/confidence mapping, CDATA escaping |
| `test_classifier.py`            | Severity scorer + 3-tier classifier           |
| `test_context_graph.py`         | Cross-finding attack-chain detection           |
| `test_cookie_analysis.py`       | HttpOnly / Secure / SameSite extraction       |
| `test_dedup.py`                 | Cross-module deduplication                     |
| `test_dork_builder.py`          | Dork-template rendering                        |
| `test_dork_module.py`           | DorkModule preview-mode + active-flag gating   |
| `test_http_client.py`           | HTTP helper error handling                     |
| `test_markdown_report.py`       | All required Markdown sections, ordering       |
| `test_nvd_client.py`            | NVD client (mocked HTTP), cache, rate limit   |
| `test_osv_parser.py`            | OSV vector parsing — **regression test for the cvss-vector-as-score bug** |
| `test_parsers.py`               | nmap / nikto line parsers                      |
| `test_poc_and_impact.py`        | PoC + impact generators                        |
| `test_settings.py`              | Mode presets, custom-headers parsing           |
| `test_surface_map.py`           | Link extraction, **bs4-fallback form parser regression**, **lstrip subdomain bug** |
| `test_target_validator.py`      | Localhost / RFC-1918 / `.gov` rejection        |
| `test_validators.py`            | Domain / IP validation primitives              |

What the **21 backend tests** cover:

- Target validation pipeline (server-side defense in depth)
- CRUD: create, list, get, delete scan
- Full lifecycle with a `_FakeEngine` patched in (doesn't touch network)
- Progress / logs / modules endpoints
- Cancel endpoint state
- Tools / settings / auth / reports endpoints
- Exploit endpoint correctly returns **501** by design

---

## Safety & ethics

1. `TargetValidator` rejects localhost, RFC-1918, `.gov`, `.mil` before
   any module runs.
2. `--confirm-authorized` AND interactive hostname-typing prompt
   (typo-stop pattern — same as `kubectl delete ns`).
3. `--dorks-active` (Google scraping) requires `--confirm-dork-scraping`
   as a second explicit opt-in.
4. `sqlmap` defaults to `--level 1 --risk 1` (non-destructive).
5. `hydra` defaults to a tiny built-in credential list; bigger
   wordlists are opt-in via `--password-list`.
6. JS analyzer **masks** any token-like string (20+ alphanumerics)
   before writing context snippets to disk — real secrets are never
   persisted.
7. Full audit trail in `output/scan.log` and `output/commands_run.txt`.
8. `/api/findings/{id}/exploit` returns **HTTP 501** by design —
   in-browser exploit execution requires per-finding scope authorization
   that HunterPy does not yet track. **Do not change this without a
   matching authorization model.**

See [SECURITY.md](SECURITY.md) for the full threat model and disclosure
process for vulnerabilities **in HunterPy itself**.

---

## Honest comparison

| Capability                       | HunterPy                  | Burp Suite Pro    | Nessus            | Nuclei (alone)   |
|----------------------------------|---------------------------|-------------------|-------------------|------------------|
| Passive recon orchestration      | ✅                         | partial (Spider)  | n/a               | n/a              |
| Active vuln scanning             | wraps nikto/sqlmap/nuclei | ✅ (own engine)   | ✅ (huge DB)      | ✅ (templates)   |
| Live request modification        | ❌                         | ✅                | ❌                | ❌               |
| Custom intruder/repeater         | ❌                         | ✅                | ❌                | ❌               |
| 200k+ vuln signatures            | ❌ (uses NVD/OSV)          | partial           | ✅                | ✅ (community)   |
| Three-tier triage classifier     | ✅                         | ❌                | ❌                | ❌               |
| AI-paste-ready report            | ✅                         | ❌                | ❌                | ❌               |
| Desktop GUI                      | ✅ (Java)                  | ✅                | partial           | ❌               |
| Web UI                           | ✅ (React, real backend)   | ❌                | ✅                | ❌               |
| REST API                         | ✅                         | partial (Pro Ent.)| ✅                | ❌               |
| Burp Suite integration           | ✅ (XML + extension)       | n/a               | ❌                | ❌               |
| Docker image w/ tools bundled    | ✅                         | ❌                | ❌                | ✅               |
| Price                            | BUSL-1.1                   | $499/yr/user      | $5k+/yr           | free             |

**Bottom line:** HunterPy is best used as a *triage layer* in front of
those tools, not as a replacement. Run it first to get a prioritised map
of where to focus the heavy hitters.

---

## Roadmap & limitations

What's deliberately **not** done in v2.1, with brutal honesty:

| Item                                          | Why we don't have it                                  |
|-----------------------------------------------|-------------------------------------------------------|
| Code-signing for the JAR / wheel              | Needs Sigstore or a real cert; out of scope for now   |
| Webhook / Slack alerts for new INTERESTING    | Trivial to add — file an issue if you need it         |
| Burp **passive** mode (live proxy ingest)     | Would need its own design; current ext loads JSON only|
| Per-finding tag persistence in DB             | Currently client-side only                            |
| Real pause/resume of in-flight scans          | `ScannerEngine` is synchronous; would need cooperative module API |
| GitHub Actions / CI workflow                  | One YAML away — left for whoever forks first          |
| Authoritative CVSS base scores from OSV       | OSV stores vectors, not scores; we use qualitative labels instead (see `test_osv_parser.py::test_does_not_parse_cvss_version_as_score`) |
| Real auth in the API                          | Stub login only; put a reverse proxy in front         |

Known **fixed** issues in v2.1 (from the v2.0 audit pass):

- `surface_map.extract_subdomains` used `str.lstrip("www.")` which strips
  any leading `w`/`.` character — fixed to a proper prefix check
- `surface_map.extract_forms` regex fallback re-wrapped form bodies as
  invalid HTML and lost action/method attrs — fixed with a single
  capture-group regex
- `osv_client.vuln_to_finding` parsed the CVSS version (e.g. `3.1`) as
  the base score — fixed to use `database_specific.severity` label
- `tool_paths._version` used `--version` for everything, missing
  gobuster (uses `version` subcommand) and nikto (uses `-Version`) —
  fixed per-tool
- `utils.http_client.head_status` claimed HEAD but did GET — fixed to
  real HEAD with 405 fallback
- Several silent `except: pass` blocks that hid real errors — replaced
  with logged warnings or narrower exception types

---

## License

[Business Source License 1.1](LICENSE) — free for internal security work
against systems you own / are authorized to test. Hosted SaaS or
third-party embedding requires a commercial license. Converts to Apache
2.0 four years after release.

For commercial licensing inquiries, file an issue (we don't have a
website yet — see "Roadmap" honesty).

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md). Most recent:

- **2.1.0** — FastAPI backend (21 tests), Burp XML exporter (15 tests),
  Burp extension, Docker image, OSV CVSS-vector bug fix, surface_map
  lstrip bug fix.
- **2.0.0** — Java/Swing GUI, React/TypeScript frontend, AI-consumable
  Markdown reports, behavioral baseline analyzer, cross-finding attack
  chains, PoC + impact analyzer, Nuclei integration, OSV.dev JS package
  scanner, hardened authorization, interactive HTML report, dork
  generator. Removed hash-cracking modules and active Google scraper.
