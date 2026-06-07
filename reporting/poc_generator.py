"""Proof-of-concept and remediation generator.

For each known finding type we produce:
  * a short, copy-pasteable PoC the analyst can run by hand
  * a concrete remediation sentence
  * relevant external references (OWASP, MDN, vendor docs)

Deliberately conservative:
  * never include working exploit payloads (no real XSS / SQLi strings)
  * curl examples are demonstrations of the *finding*, not attacks
  * for findings we don't recognize we still produce a generic block so
    the report stays uniform
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PoC:
    title: str
    finding_type: str
    description: str
    steps: List[str] = field(default_factory=list)
    sample_command: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------- per-type PoC builders ----------
def _poc_git_exposed(f: Dict[str, Any]) -> PoC:
    url = f.get("url", "<target>")
    return PoC(
        title="Verify exposed .git directory",
        finding_type=f.get("type", ""),
        description="A .git directory accessible via HTTP can leak the full "
                    "source-tree and commit history of the application.",
        steps=[
            f"1. Fetch the HEAD file:  curl -sI {url}",
            f"2. Confirm a refs file exists:  curl -s {url.rsplit('/',1)[0]}/refs/heads/main",
            "3. If both return 200, the repo can be reconstructed with tools "
            "like `git-dumper`. Do NOT run automated cloners against scoped "
            "targets without explicit permission — verifying status is enough.",
        ],
        sample_command=f"curl -sI {url}",
        remediation="Block requests to paths starting with `.git/` at the "
                    "web-server or CDN layer, and remove the directory from "
                    "the deployed artifact.",
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage",
            "https://iampava.com/exposed-git-repository-attack",
        ],
    )


def _poc_env_exposed(f: Dict[str, Any]) -> PoC:
    url = f.get("url", "<target>/.env")
    return PoC(
        title="Verify exposed .env file",
        finding_type=f.get("type", ""),
        description=".env files often hold API keys, DB credentials and "
                    "secret tokens in cleartext.",
        steps=[
            f"1. HEAD only — confirm reachability without downloading body:",
            f"   curl -sI {url}",
            "2. If status is 200, treat it as a confirmed credential leak. "
            "Rotate any secrets that may have been in the file.",
        ],
        sample_command=f"curl -sI {url}",
        remediation="Move `.env` files outside the web root, deny via "
                    "web-server rules, and rotate any secrets that were "
                    "ever served publicly.",
        references=["https://cwe.mitre.org/data/definitions/538.html"],
    )


def _poc_admin_panel(f: Dict[str, Any]) -> PoC:
    url = f.get("url", "<target>/admin/")
    return PoC(
        title="Manually inspect admin interface",
        finding_type=f.get("type", ""),
        description="An administrative interface reachable without an auth "
                    "wall is a high-value target for brute-force, default "
                    "credentials, and forgotten test accounts.",
        steps=[
            f"1. Visit {url} in a browser using an account-less profile.",
            "2. Note whether the page loads, redirects to login, or 403s.",
            "3. If a login page is present, check headers/cookies for "
            "framework hints (CMS, version, lockout policy).",
            "4. Do NOT run automated credential-brute-forcers without a "
            "written scope statement permitting that test.",
        ],
        sample_command=f"curl -sI {url}",
        remediation="Place administrative paths behind a VPN or IP allow-list, "
                    "enforce strong MFA, and rate-limit login attempts.",
        references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
    )


def _poc_missing_header(f: Dict[str, Any]) -> PoC:
    header = (f.get("evidence") or {}).get("header_name") \
             or f.get("header_name") or "<header>"
    return PoC(
        title=f"Confirm missing security header: {header}",
        finding_type=f.get("type", ""),
        description=f"The {header} header is absent on this response.",
        steps=[
            f"1. Re-fetch the page and grep the headers:",
            f"   curl -sI {f.get('url', '<target>')} | grep -i '{header}'",
            "2. If the header truly never appears across any sample page, "
            "this is a real gap, not a one-off.",
        ],
        sample_command=f"curl -sI {f.get('url', '<target>')}",
        remediation=_HEADER_REMEDIATION.get(header.lower(),
                    f"Set the {header} response header per OWASP guidance."),
        references=["https://owasp.org/www-project-secure-headers/"],
    )


def _poc_weak_csp(f: Dict[str, Any]) -> PoC:
    return PoC(
        title="Review CSP policy for unsafe directives",
        finding_type=f.get("type", ""),
        description="The Content-Security-Policy includes directives that "
                    "weaken its protection (e.g. unsafe-inline / unsafe-eval).",
        steps=[
            f"1. Capture the full policy:  curl -sI {f.get('url','<target>')}"
            " | grep -i content-security-policy",
            "2. Audit each source list — remove unsafe-inline, unsafe-eval, "
            "wildcard `*`, and `data:` for script-src.",
            "3. Replace inline scripts with nonces or hashes.",
        ],
        remediation="Adopt a strict CSP with nonces; remove unsafe-inline / "
                    "unsafe-eval; pin allowed source domains.",
        references=["https://developer.mozilla.org/docs/Web/HTTP/CSP",
                    "https://csp-evaluator.withgoogle.com/"],
    )


def _poc_cors(f: Dict[str, Any]) -> PoC:
    return PoC(
        title="Confirm CORS misconfiguration",
        finding_type=f.get("type", ""),
        description="The server appears to reflect arbitrary origins, which "
                    "can let attacker-controlled pages read authenticated "
                    "responses.",
        steps=[
            f"1. Repeat the request with a controlled Origin header:",
            f"   curl -sI -H 'Origin: https://evil.example' "
            f"{f.get('url', '<target>')}",
            "2. Inspect Access-Control-Allow-Origin and "
            "Access-Control-Allow-Credentials in the response.",
            "3. If ACAO echoes back your Origin AND ACAC is `true`, "
            "this is a real cross-origin data-disclosure issue.",
        ],
        remediation="Use an allow-list of trusted origins; never combine "
                    "`Access-Control-Allow-Origin: *` with credentials; "
                    "default to deny.",
        references=["https://portswigger.net/web-security/cors"],
    )


def _poc_cve(f: Dict[str, Any]) -> PoC:
    ev = f.get("evidence") or {}
    cve = ev.get("cve_id") or ev.get("osv_id") or "<CVE-ID>"
    pkg = ev.get("product") or ev.get("package") or "the affected component"
    ver = ev.get("version") or "<version>"
    fixed = ev.get("fixed_versions") or []
    fixed_str = f"Fixed in: {', '.join(fixed)}" if fixed else \
                "Confirm the fixed version in the upstream advisory."
    return PoC(
        title=f"Verify {cve} affects {pkg} {ver}",
        finding_type=f.get("type", ""),
        description=f"{cve} reportedly affects {pkg} version {ver} as "
                    "extracted from the public response / source.",
        steps=[
            "1. Validate the version manually — banners and bundled file "
            "names can be wrong or stripped.",
            "2. Read the upstream advisory linked in the references.",
            f"3. {fixed_str}",
            "4. Treat this as a *lead*, not a confirmed exploit, until you "
            "have a reproducible PoC against the running instance.",
        ],
        remediation=f"Upgrade {pkg} to a fixed release; if upgrading is "
                    "infeasible, apply vendor-recommended mitigations.",
        references=ev.get("references") or [
            f"https://nvd.nist.gov/vuln/detail/{cve}"
        ],
    )


def _poc_sensitive_keyword(f: Dict[str, Any]) -> PoC:
    ev = f.get("evidence") or {}
    return PoC(
        title="Triage sensitive keyword hit in JavaScript",
        finding_type=f.get("type", ""),
        description=f"A sensitive-looking identifier ('{ev.get('keyword','?')}') "
                    "was matched near a literal in client-side JS. This may "
                    "be a leaked secret OR a perfectly normal variable name.",
        steps=[
            f"1. Open the file: {ev.get('file', f.get('url',''))}",
            f"2. Inspect around line {ev.get('line','?')} for actual value.",
            "3. If a real key/token/credential is present, rotate it "
            "immediately and audit access logs.",
            "4. If it's only a variable name, mark as false-positive in the "
            "report.",
        ],
        remediation="Never ship real secrets in client-side bundles. Use a "
                    "backend proxy for any API that needs authentication.",
        references=["https://cwe.mitre.org/data/definitions/798.html"],
    )


def _poc_generic(f: Dict[str, Any]) -> PoC:
    return PoC(
        title=f.get("title") or "Manual verification recommended",
        finding_type=f.get("type", "unknown"),
        description=f.get("details") or f.get("description") or
                    "Review this finding manually using the URL and evidence "
                    "provided in the report.",
        steps=[
            "1. Reproduce the request that produced this finding.",
            "2. Confirm the observation is consistent across retries.",
            "3. Determine whether it is a real issue or a benign artifact.",
        ],
        sample_command=f"curl -sI {f.get('url', '<target>')}",
        remediation="N/A — verify finding first.",
        references=[],
    )


_HEADER_REMEDIATION = {
    "content-security-policy":
        "Add a strict Content-Security-Policy. Start with default-src 'self' "
        "and tighten from there.",
    "strict-transport-security":
        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`"
        " on HTTPS responses, then submit the domain to the HSTS preload list.",
    "x-frame-options":
        "Send `X-Frame-Options: SAMEORIGIN` (or use CSP frame-ancestors).",
    "x-content-type-options":
        "Send `X-Content-Type-Options: nosniff` on every response.",
    "referrer-policy":
        "Send `Referrer-Policy: strict-origin-when-cross-origin`.",
    "permissions-policy":
        "Send a `Permissions-Policy` header explicitly disabling features "
        "your app doesn't need.",
}


# ---------- dispatcher ----------
def _poc_dork_suggestion(f: Dict[str, Any]) -> PoC:
    ev = f.get("evidence") or {}
    template = ev.get("template", "unknown")
    queries = ev.get("queries", []) or []
    urls    = ev.get("google_urls", []) or []
    sample_query = queries[0] if queries else "n/a"
    steps = [
        f"1. These dorks were generated for template '{template}'. They were "
        "NOT executed — Google scraping is off by default.",
        "2. Open each URL below in your browser (or your AI of choice) to "
        "review the real Google results manually.",
    ] + [f"   • {u}" for u in urls[:5]]
    if len(urls) > 5:
        steps.append(f"   • … and {len(urls) - 5} more (see evidence.google_urls).")
    steps.append("3. Treat any matching public document / endpoint as "
                 "informational unless it reveals secrets, then escalate.")
    return PoC(
        title=f"Review Google dork bundle: {template}",
        finding_type=f.get("type", "dork_suggestion"),
        description=("Auto-generated dorks for this target. The tool did "
                     "not query Google — you must review manually."),
        steps=steps,
        sample_command=f"# Sample query (paste into Google):\n{sample_query}",
        remediation=("Remove sensitive files / endpoints surfaced by these "
                     "dorks from public indexing; configure robots.txt and "
                     "noindex headers; rotate any exposed credentials."),
        references=[
            "https://www.exploit-db.com/google-hacking-database",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage",
        ],
    )


def _poc_dork_hit(f: Dict[str, Any]) -> PoC:
    ev = f.get("evidence") or {}
    url = f.get("url", "")
    return PoC(
        title="Manually validate the dork hit",
        finding_type=f.get("type", "dork_hit"),
        description=(f"Google indexed this URL in response to "
                     f"`{ev.get('dork_query', '')}`. The hit itself does "
                     "not prove a vulnerability — open the URL and confirm."),
        steps=[
            f"1. Open {url} in an incognito browser.",
            "2. Determine whether the page exposes credentials, source code, "
            "or other sensitive material.",
            "3. If sensitive material is present, escalate as the underlying "
            "finding-type (e.g. env_exposed / sensitive_data_exposure).",
        ],
        sample_command=f"curl -sI {url}",
        remediation=("Block search-engine indexing of the path "
                     "(`robots.txt`, `X-Robots-Tag: noindex`), or remove the "
                     "file from the web root entirely."),
        references=[
            "https://developers.google.com/search/docs/crawling-indexing/robots/intro",
        ],
    )


# --------------------------------------------------------------------------
# Symfony intel-pack PoC builders. Each one cites the source SECREP* report
# so the analyst can read the original incident.
# --------------------------------------------------------------------------
def _poc_symfony_profiler(f: Dict[str, Any]) -> PoC:
    url = f.get("url", "<target>/_profiler/")
    base = url.rsplit("/_profiler", 1)[0] or url
    return PoC(
        title="Verify Symfony profiler exposure",
        finding_type=f.get("type", ""),
        description=("Symfony's debug profiler is reachable from the public "
                     "internet. In the SECREP1 + SECREP2 incidents this was "
                     "the first link in a full-source-disclosure chain."),
        steps=[
            f"1. curl -sI {base}/_profiler/  →  expect HTTP 200",
            f"2. curl -s {base}/_profiler/phpinfo | head  →  PHP version + env "
            "vars (DATABASE_URL, APP_SECRET, OAUTH_*).",
            f"3. curl -s '{base}/_profiler/open?file=config/packages/security.yaml&line=1' "
            "→ reads any file the web user can read.",
            "4. Do NOT navigate the profiler routes that allow token / URL "
            "deletion in dev mode — those are state-changing.",
        ],
        sample_command=f"curl -sI {base}/_profiler/",
        remediation=("Set APP_ENV=prod and APP_DEBUG=0 in production. "
                     "Remove the WebProfilerBundle entry from "
                     "config/bundles.php for prod, or restrict the profiler "
                     "by IP in web/.htaccess / nginx / FrameworkBundle "
                     "config (`profiler: { only_exceptions: false, "
                     "collect: !php/const App\\Kernel::PROD }`). "
                     "Rotate APP_SECRET + all DB and OAuth credentials "
                     "that were observable via /_profiler/phpinfo."),
        references=[
            "https://symfony.com/doc/current/profiler.html",
            "docs/threat-intel/SECREP-symfony-edu.pdf",
            "docs/threat-intel/SECREP-murilocarapeba-clinic.pdf",
        ],
    )


def _poc_symfony_lfi(f: Dict[str, Any]) -> PoC:
    url = f.get("url", "<target>")
    base = url.split("/_profiler", 1)[0]
    return PoC(
        title="Verify Symfony profiler LFI (/_profiler/open)",
        finding_type=f.get("type", ""),
        description=("/_profiler/open?file=… serves any file path the web "
                     "user can read. In the SECREP2 incident this was used "
                     "to dump security.yaml, doctrine.yaml, services.yaml, "
                     "and the entire src/ tree."),
        steps=[
            f"1. curl -s '{base}/_profiler/open?file=config/packages/security.yaml&line=1' "
            "→ shows the firewall config.",
            f"2. curl -s '{base}/_profiler/open?file=.env&line=1'  →  often "
            "exposes APP_SECRET + DATABASE_URL.",
            f"3. curl -s '{base}/_profiler/open?file=config/packages/doctrine.yaml&line=1' "
            "→ enumerates every DB connection (default, db2, ticketing).",
            "4. Do NOT request anything outside the project root — even "
            "`/etc/passwd` would land you in unauthorised-access territory.",
        ],
        sample_command=(f"curl -s '{base}/_profiler/open"
                        "?file=config/packages/security.yaml&line=1'"),
        remediation=("Disable the profiler in production (see "
                     "`symfony_profiler_exposed` remediation). The /open "
                     "endpoint is only registered when "
                     "framework.profiler.only_exceptions is unset AND "
                     "kernel.debug is true."),
        references=[
            "https://symfony.com/doc/current/profiler.html#access-info",
            "docs/threat-intel/SECREP-symfony-edu.pdf",
        ],
    )


def _poc_symfony_app_env_injection(f: Dict[str, Any]) -> PoC:
    url = f.get("url", "<target>")
    base = url.split("?", 1)[0]
    return PoC(
        title="Verify Symfony APP_ENV query-string injection",
        finding_type=f.get("type", ""),
        description=("Symfony Console's ArgvInput reads $_SERVER['argv']. A "
                     "request like `?+--env=dev` injects an extra CLI "
                     "argument that flips APP_ENV to dev on the request "
                     "scope, re-enabling the profiler. Documented in the "
                     "SECREP-symfony-upstream-issues GitHub thread."),
        steps=[
            f"1. curl -s '{base}/?+--env=dev' | grep -i profiler  →  if the "
            "response now contains profiler markers, you have flipped env.",
            f"2. curl -s '{base}/_profiler/'  →  may now be reachable.",
            "3. Stop probing — anything further is exploitation.",
        ],
        sample_command=f"curl -s '{base}/?+--env=dev' -o /dev/null -w '%{{http_code}}\\n'",
        remediation=("Upgrade symfony/runtime to >= 5.4.46 / 6.x. As a "
                     "compensating control, sanitise $_SERVER['argv'] "
                     "in your public/index.php before the kernel boots."),
        references=[
            "docs/threat-intel/SECREP-symfony-upstream-issues.pdf",
            "https://github.com/symfony/symfony/security/advisories",
        ],
    )


def _poc_symfony_exposed_credentials(f: Dict[str, Any]) -> PoC:
    ev = f.get("evidence") or {}
    needle = ev.get("needle", "<credential>")
    return PoC(
        title="Triage exposed credential in landing page",
        finding_type=f.get("type", ""),
        description=(f"The token `{needle}` appears with a value-shaped "
                     "string on the landing page itself — almost certainly "
                     "a forgotten dump()/dd()/print_r() debug call."),
        steps=[
            f"1. Re-open {f.get('url', '<target>')} in an incognito browser.",
            "2. View source and search for the credential identifier.",
            "3. If it is real, rotate the secret immediately and audit any "
            "service that authenticates with it.",
            "4. Grep the codebase for `dump(`, `dd(`, `print_r(`, "
            "`var_dump(` to find the leaking call site.",
        ],
        sample_command=f"curl -s {f.get('url', '<target>')} | grep -i {needle}",
        remediation=("Never call Symfony's dump()/dd() with framework "
                     "internals in production. Add an integration test that "
                     "fails the CI build if response bodies contain "
                     "APP_SECRET / DATABASE_URL / OAuth secret patterns."),
        references=["docs/threat-intel/SECREP-symfony-edu.pdf"],
    )


def _poc_symfony_legacy_parameters(f: Dict[str, Any]) -> PoC:
    url = f.get("url", "<target>")
    return PoC(
        title="Verify legacy Symfony parameters.yml exposure",
        finding_type=f.get("type", ""),
        description=("The legacy app/config/parameters.yml file is reachable "
                     "via /app_dev.php/_profiler/open. It typically "
                     "contains database_password, secret, mailer credentials, "
                     "and any other framework-level secrets."),
        steps=[
            f"1. curl -s '{url}'  →  inspect the YAML payload.",
            "2. Identify every credential and rotate it on the corresponding "
            "service (DB, SMTP, third-party APIs).",
            "3. Confirm the audit trail of access to those services around "
            "the time the file was first exposed.",
        ],
        sample_command=f"curl -s '{url}'",
        remediation=("Disable APP_ENV=dev / app_dev.php in production. Move "
                     "parameters.yml outside the web root and rotate every "
                     "credential it ever contained."),
        references=["docs/threat-intel/SECREP-symfony-upstream-issues.pdf"],
    )


def _poc_imagemagick(f: Dict[str, Any]) -> PoC:
    return PoC(
        title="Triage vulnerable ImageMagick version",
        finding_type=f.get("type", ""),
        description=("ImageMagick 6.9.10 and similar versions are vulnerable "
                     "to the ImageTragick family (CVE-2016-3714) and "
                     "CVE-2021-4219. The risk is real whenever the web "
                     "stack accepts user-supplied images for processing."),
        steps=[
            "1. Verify the running ImageMagick version on the server: "
            "convert -version",
            "2. Inspect /etc/ImageMagick-6/policy.xml — confirm that "
            "MVG, MSL, EPHEMERAL, URL, HTTPS, HTTP, FTP, MAILTO, TEXT and "
            "PS coders are all <policy rights=\"none\" pattern=\"…\">.",
            "3. Audit every PHP imagick / GD path that reads "
            "user-uploaded files.",
        ],
        sample_command="convert -version",
        remediation=("Upgrade ImageMagick to >= 6.9.12-34 (or 7.x). Tighten "
                     "policy.xml. If you don't need image processing on "
                     "user uploads, route them through a sandboxed "
                     "service instead."),
        references=[
            "https://imagetragick.com/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-4219",
            "docs/threat-intel/SECREP-murilocarapeba-clinic.pdf",
        ],
    )


def _poc_eol_php(f: Dict[str, Any]) -> PoC:
    return PoC(
        title="Triage end-of-life PHP version",
        finding_type=f.get("type", ""),
        description=("The server runs an EOL PHP release. No security "
                     "patches are published upstream — combined with "
                     "default-empty disable_functions this is a trivial "
                     "RCE pivot point (SECREP1)."),
        steps=[
            "1. php -v on the server  →  confirm version.",
            "2. grep -i disable_functions /etc/php/*/php.ini  →  check that "
            "exec, system, shell_exec, passthru, proc_open, popen, "
            "curl_exec are listed.",
            "3. Inventory every application that runs on this PHP binary "
            "before upgrading — a PHP upgrade can break ext-imagick, "
            "deprecated mysql_* calls, and old framework releases.",
        ],
        sample_command="php -v",
        remediation=("Upgrade to a supported PHP release (8.2+). At "
                     "minimum, set disable_functions in php.ini to the "
                     "list above, and apply a WAF rule blocking known "
                     "RCE strings on every endpoint that accepts file "
                     "uploads."),
        references=[
            "https://www.php.net/eol.php",
            "docs/threat-intel/SECREP-murilocarapeba-clinic.pdf",
        ],
    )


def _poc_unrestricted_upload(f: Dict[str, Any]) -> PoC:
    url = f.get("url", "<target>")
    return PoC(
        title="Manually validate the file-upload endpoint",
        finding_type=f.get("type", ""),
        description=("The endpoint accepts uploads with insufficient "
                     "server-side validation. In the SECREP1 incident this "
                     "was the entry point that, combined with vulnerable "
                     "ImageMagick + EOL PHP, would have allowed RCE."),
        steps=[
            f"1. Confirm the endpoint accepts your test image: curl "
            f"-F 'image=@small.jpg' {url}",
            "2. Inspect the storage path returned for the upload. If it is "
            "inside the web root, browse to it — anything that returns the "
            "exact bytes you uploaded confirms the file was stored.",
            "3. Try the standard polyglot tests (.php.jpg double extension, "
            "MSL/PDF polyglot, GIF89a + PHP) — do NOT submit a working "
            "webshell unless the engagement scope explicitly permits it.",
        ],
        sample_command=f"curl -F 'image=@small.jpg' {url}",
        remediation=("Validate uploads server-side: check magic bytes, "
                     "re-encode the image with ImageMagick, store it "
                     "OUTSIDE the web root, and serve it via a "
                     "controller that sets Content-Disposition: "
                     "attachment + a sandboxed Content-Type."),
        references=[
            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
            "docs/threat-intel/SECREP-murilocarapeba-clinic.pdf",
        ],
    )


_BUILDERS = {
    "git_exposed":              _poc_git_exposed,
    "env_exposed":              _poc_env_exposed,
    "config_exposed":           _poc_env_exposed,
    "admin_panel":              _poc_admin_panel,
    "missing_security_header":  _poc_missing_header,
    "weak_csp":                 _poc_weak_csp,
    "cors_wildcard":            _poc_cors,
    "cors_reflection":          _poc_cors,
    "cors_with_credentials":    _poc_cors,
    "cors_null_origin":         _poc_cors,
    "cve":                      _poc_cve,
    "sensitive_keyword_in_js":  _poc_sensitive_keyword,
    "dork_suggestion":          _poc_dork_suggestion,
    "dork_hit":                 _poc_dork_hit,

    # --- Symfony / SECREP* intel pack -----------------------------------
    "symfony_profiler_exposed":   _poc_symfony_profiler,
    "symfony_profiler_phpinfo":   _poc_symfony_profiler,
    "symfony_profiler_search":    _poc_symfony_profiler,
    "symfony_legacy_profiler":    _poc_symfony_profiler,
    "symfony_legacy_dev_front_controller": _poc_symfony_profiler,
    "symfony_fragment_endpoint":  _poc_symfony_profiler,
    "symfony_profiler_lfi":       _poc_symfony_lfi,
    "symfony_app_env_injection":  _poc_symfony_app_env_injection,
    "symfony_app_debug_injection":_poc_symfony_app_env_injection,
    "symfony_exposed_credentials":_poc_symfony_exposed_credentials,
    "symfony_legacy_parameters_yml": _poc_symfony_legacy_parameters,
    "imagemagick_vulnerable_version": _poc_imagemagick,
    "eol_php_with_dangerous_functions": _poc_eol_php,
    "unrestricted_file_upload":   _poc_unrestricted_upload,
}


class PoCGenerator:
    """Public API used by the report engine."""

    def generate(self, finding: Dict[str, Any]) -> PoC:
        ftype = (finding.get("type") or "").lower()
        builder = _BUILDERS.get(ftype, _poc_generic)
        try:
            return builder(finding)
        except Exception:
            return _poc_generic(finding)

    def generate_many(self, findings: List[Dict[str, Any]]) -> Dict[str, PoC]:
        out: Dict[str, PoC] = {}
        for f in findings:
            fid = _finding_key(f)
            out[fid] = self.generate(f)
        return out


def _finding_key(f: Dict[str, Any]) -> str:
    """Stable per-finding key used to match PoCs + impacts in the report."""
    return f.get("id") or f.get("finding_uid") or (
        f"{f.get('module','')}|{f.get('type','')}|{f.get('url','')}|"
        f"{(f.get('title') or '')[:60]}"
    )
