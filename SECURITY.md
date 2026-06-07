# Security Policy

## Threat model for the tool itself

HunterPy parses adversarial-ish data (HTML / JS from arbitrary scan
targets, plus optionally JSON from the user's disk). The relevant
attack surface inside HunterPy itself:

| Surface                          | Risk                          | Mitigation in place                                |
|----------------------------------|-------------------------------|----------------------------------------------------|
| `requests` / stdlib HTTP fetches | SSRF if target is attacker-influenced | `TargetValidator` blocks localhost / RFC-1918 / `.gov` / `.mil`; scope file support |
| `BeautifulSoup` HTML parsing     | Crafted HTML triggering parser bugs | Standard `html.parser` (stdlib); bounded read size in `http_client.py` |
| Regex over JS source             | Catastrophic backtracking     | Patterns are linear; sample sizes capped to 300 KB |
| JSON report reading (Java GUI)   | Parser bug on hostile JSON    | The GUI is intended to read reports HunterPy itself produced. For untrusted JSON, use a hardened parser like Jackson. |
| Subprocess wrappers (nmap/nikto/sqlmap/etc.) | Argument injection            | All args passed as a `list`, never shell-interpolated |
| SQLite DB                        | n/a (local file, not networked) | —                                                  |
| `--dorks-active` Google scraping | ToS violation + IP ban         | Disabled by default; requires `--dorks-active` AND `--confirm-dork-scraping` |

## What HunterPy will never do, by design

- Send attack payloads in `passive` mode
- Auto-run `hashcat` / `john` against discovered hashes (removed in v2.0)
- Scrape Google by default (preview-only dork generation)
- Log raw secret values found in JavaScript (long tokens are `<redacted>`)
- Read or write outside the configured `--output` directory

## Reporting a vulnerability

If you find a vulnerability **in HunterPy itself** (the tool, not in
something it discovered on a target), please report it privately:

1. **Do not** open a public GitHub issue.
2. Email a draft advisory to the project maintainer (see `pyproject.toml`
   if/when packaged).
3. Allow up to 30 days for triage and 90 days for a coordinated fix
   before public disclosure.

We will credit you in `CHANGELOG.md` unless you ask otherwise.

## Out of scope

- Vulnerabilities in the **target systems** you scan (those are findings,
  not HunterPy bugs).
- Bypasses of `--confirm-authorized` that require a malicious actor with
  shell access to your machine (already game over).
- Issues in external CLI tools (`nmap`, `nikto`, `sqlmap`, `nuclei`,
  `hydra`). Report those upstream.
