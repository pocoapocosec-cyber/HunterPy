# HunterPy Verification Subsystem

This document describes the **verification** (a.k.a. "safe exploit
confirmation") subsystem introduced in HunterPy v2.3. Read it end-to-end
before enabling `--verify` on a live target. It also exists so legal /
compliance teams reviewing HunterPy for adoption have something concrete
to point at.

> **One-line summary:** the verifier takes findings that HunterPy already
> *detected* and runs the *least-invasive request that proves
> exploitability*. It is **not** an exploitation framework and it does
> **not** drop webshells, persist code, or pivot. Operators who need
> those capabilities should use a real C2 framework (Sliver, Mythic,
> Cobalt Strike) under explicit SOW terms.

---

## Why this exists (and what it isn't)

A scanner that only *detects* leaves the operator with a list of "this
might be a problem" — they still have to manually verify each one before
writing the report. That's tedious, and tedious work invites shortcuts.

A scanner that *auto-exploits* every critical finding is the worst of
both worlds: scope creep, SOW violations, "we got a shell on prod
before the blue team was briefed", and (eventually) a phone call from a
prosecutor. Every mature pentest tool draws a hard line here: detection
is automated, exploitation requires an operator in the loop. HunterPy
follows that convention.

What the verifier adds is a *third path*: per-finding, operator-gated,
least-invasive proof-of-exploitability checks with full evidence
capture. The operator sees `"Symfony profiler exposed at /_profiler/" →
verify? [y]es` and gets back `"confirmed — phpinfo() returns 200, leaked
keys APP_SECRET/DATABASE_URL (values fingerprinted)"`. No shell. No
persistence. Provable in court.

### What the verifier WILL do

- Re-fetch the originally-flagged URL with a unique `X-HunterPy-Verify`
  header (so blue teams can correlate).
- Read a single, boring file (`/etc/hostname`) to prove arbitrary file
  read via a confirmed LFI.
- Look for sensitive environment variable *names* in a known
  `phpinfo()` exposure, and SHA-256 the *values* into the proof.
- Upload a plain `.txt` marker file (never `.php`/`.phtml`/`.phar`/etc.)
  to a confirmed unrestricted-upload endpoint, GET it back, then issue a
  best-effort DELETE.
- Send the documented `?+--env=dev` query and diff the response against
  the baseline (CVE-2024-50340).
- Capture every byte sent and received into a per-finding evidence
  bundle.

### What the verifier WILL NOT do

- Drop a webshell, backdoor, or any persistent payload. Ever.
- Brute-force credentials. (There's a separate Hydra module for the
  cases that need it; that's also operator-gated.)
- Pivot to other hosts or scan beyond the authorization scope.
- Submit SQL UNION dumps, full LFI directory walks, or RCE payloads
  beyond a single time-delay / OOB-callback proof.
- Run any probe whose safety level exceeds what the *authorization
  file* allows.

---

## Threat model

We assume:

1. The operator is a legitimate pentester on a paid engagement.
2. The SOW permits non-destructive verification of detected issues.
3. The target is *not* a honeypot trying to legally entrap the operator
   (the typo-stop and authorization file exist partly to protect against
   accidental scope creep that could be construed that way).
4. The collaborator endpoint is reachable from the target (if used).
5. The HunterPy machine is reasonably trusted — the signing key
   (`~/.hunterpy/auth.key`) is treated like an SSH private key.

We do **not** assume:

1. That the operator will read every CLI flag — hence the typo-stop
   confirmation, the signed auth file, and the per-finding prompts.
2. That the network is friendly — hence the WAF backoff (429/403 +
   known WAF markers abort the phase).
3. That the target is a single host — every finding's hostname is
   re-checked against the authorization scope at probe time, not just
   at scan start.

---

## Control flow

```
   [scan]
      |
      v
   [phases 1-5 (recon → scanning → injection → auth → hashes)]
      |
      v
   [classification + dedup + context graph]
      |
      v
   [Phase 6: verifier]  <-- ONLY runs if --verify is set
      |
      |--> load + signature-check authorization file
      |    (fail closed: missing/expired/out-of-scope = no verify)
      |
      |--> for each INTERESTING / CRITICAL / HIGH finding with a probe:
      |       prompt operator (y/n/a/q) unless --verify-non-interactive
      |       re-check scope + safety vs authorization
      |       run probe.execute() with timeouts + consent header
      |       write evidence bundle to <output>/verification/<uid>/
      |       attach VerificationResult to finding dict
      |       sleep 1/rate_limit
      |       if WAF block detected -> abort whole phase
      |
      v
   [reports include verification table]
```

---

## Authorization file

The authorization file is a JSON document with an HMAC-SHA256 signature.
It declares:

| field               | meaning                                                            |
|---------------------|--------------------------------------------------------------------|
| `engagement`        | Free-form label for the engagement (e.g. SOW number).              |
| `operator`          | Human name / email — appears in evidence bundles.                  |
| `hostnames`         | List of allowed hostnames or `fnmatch` globs (`*.example.com`).    |
| `issued_at`         | ISO-8601 timestamp when the file was generated.                    |
| `expires_at`        | ISO-8601 timestamp after which the verifier refuses to run.        |
| `max_safety_level`  | `read_only` < `noisy_read` < `trivial_write` < `destructive`.      |
| `allow_destructive` | Boolean. Must also set `max_safety_level=destructive` to take effect. |
| `notes`             | Free-form (e.g. SOW link, ticket ID).                              |
| `signature`         | Hex HMAC-SHA256 of all the above, sorted-keys JSON, with auth key. |

### Generating one

```bash
python main.py --verify-issue-auth ./engagement-foo.auth.json \
    --verify-engagement "Acme/2026Q2/SOW-471" \
    --verify-operator "you@yourfirm.example" \
    --verify-hostnames acme.example.com '*.staging.acme.example.com' \
    --verify-valid-days 14 \
    --verify-max-safety trivial_write \
    --verify-notes "https://internal.acme.example/sow/471"
```

This:

1. Loads (or generates, on first use) the HMAC key from
   `$HUNTERPY_AUTH_KEY` or `~/.hunterpy/auth.key` (0600).
2. Signs the payload and writes it to the path you gave.
3. Prints the parsed contents back to you so you can sanity-check.

**Lose the key and you must reissue every existing file.** That's
intentional: it ties an authorization to a specific operator workstation
and prevents one engagement's auth file from being shared casually.

### Running with it

```bash
python main.py -t acme.example.com --mode passive \
    --confirm-authorized --i-am-authorized \
    --verify --verify-auth-file ./engagement-foo.auth.json
```

If you want fully unattended verification (CI runs after a passive
scan):

```bash
python main.py -t acme.example.com --mode passive \
    --confirm-authorized --i-am-authorized \
    --verify --verify-auth-file ./engagement-foo.auth.json \
    --verify-non-interactive \
    --verify-rate-limit 0.2 \
    --verify-max-findings 25
```

---

## Safety levels

| Level           | What it permits                                                | Examples                                                       |
|-----------------|-----------------------------------------------------------------|----------------------------------------------------------------|
| `read_only`     | GET requests only. No body, no state change.                   | Re-fetch `.git/HEAD`. Read `/etc/hostname` via LFI.            |
| `noisy_read`    | Read-only but visible to the SOC (OOB callbacks, time-delay SQLi). | SSRF→collaborator. SQLi with 3s sleep.                       |
| `trivial_write` | A single write that creates a marker we attempt to clean up.   | Upload `hpv_<uuid>.txt` (plain text), GET, DELETE.             |
| `destructive`   | Writes we cannot reliably clean up. **Avoid.**                  | None shipped. Reserved for engagement-specific custom probes.  |

The verifier enforces three independent checks before running any
probe: the authorization file's `max_safety_level`, the per-CLI
`--verify-allow-destructive` flag, and the probe's own declared
`safety_level`. All three must agree.

---

## Evidence bundles

Every verification attempt writes to
`<output_dir>/verification/<finding_uid>/`. The layout:

```
verification/<finding_uid>/
├── result.json              # full VerificationResult (status, proof, exchanges)
├── proof.txt                # short human-readable proof line
├── authorization.json       # copy of the active authorization (no signing key)
├── _written_at              # ISO-8601 timestamp
├── cleanup.log              # optional, written when probes attempted cleanup
└── exchanges/
    ├── 000.http             # raw request + response, one per network call
    ├── 001.http
    └── ...
```

### Secret redaction

`evidence.py` carries a small list of credential patterns
(`APP_SECRET`, `DATABASE_URL`, `mailer_password`, `OAUTH_*_SECRET`,
AWS access keys). When a captured request or response body matches any
of them, the *value* is replaced with `<REDACTED-sha256:<first16>>`
before the body is written to disk. The fingerprint is enough to prove
"yes we saw this secret and it's still on the box" without putting the
secret in your evidence bundle.

If you discover a pattern that should be in the redaction list, add it
to `_REDACT_PATTERNS` in `modules/exploit/evidence.py` and bump
`tests/test_verifier_evidence.py`.

---

## Collaborator (out-of-band callbacks)

Some classes of finding can only be safely *proven* via an out-of-band
signal — SSRF, blind XXE, command-injection-without-output. The
verifier supports two backends:

- **`LocalCollaborator`** (default) — spins up an HTTP listener on
  `127.0.0.1:<random>` for the duration of Phase 6. Useful for local
  testing and for engagements where the target can reach the operator's
  machine.

- **`ExternalCollaboratorClient`** — points at an HTTP recorder you
  control. Pass `--verify-collaborator-url https://collab.your-domain/`.
  HunterPy expects a `GET <url>/poll?token=<t>` endpoint that returns
  JSON `{"hits":[{...}]}`. A 25-line shim around
  [`interactsh-server`](https://github.com/projectdiscovery/interactsh)
  works fine; see the `contrib/` directory if you ship one.

Tokens are 16-byte URL-safe random strings prefixed with `hpv-`. They
appear in every captured exchange so an auditor can correlate the
network capture with the recorded callback.

---

## Adding a new probe

1. Create `modules/exploit/probes/<framework>.py`.
2. Subclass `Probe`, declare `probe_name` and `safety_level`, implement
   `execute()` returning a `VerificationResult`.
3. Decorate the class with `@register_probe("finding_type", ...)`.
4. Add an import to `modules/exploit/probes/__init__.py`.
5. Write tests under `tests/test_<framework>_probe.py`.

### Rules

- **Make exactly one decision per probe.** "Did this prove the finding?"
  is the *only* question to answer. Anything beyond that is exploitation.
- **Use `self._get()`** so exchanges are captured automatically.
- **Never log secrets.** Hash them with `hashlib.sha256(...).hexdigest()[:16]`
  and put the fingerprint in `proof_artifacts`.
- **Pick the boring proof.** If you can prove LFI by reading
  `/etc/hostname`, do that — don't read `/etc/shadow` because it's
  "more impressive". The point is *evidence*, not flair.
- **Clean up.** If your probe writes anything, attempt a cleanup and
  honestly report `cleanup_successful` (including `False`).
- **Refuse to chain.** A probe never calls another probe. If you find
  yourself needing a chain, file an issue — the operator should drive
  chains manually.

---

## Things the verifier deliberately doesn't do

| Capability                                           | Why we won't ship it                                                |
|------------------------------------------------------|----------------------------------------------------------------------|
| Auto-upload `.php` / `.phtml` / `.phar` webshells    | Persistent, modifies prod state, detectable in 30s, marks tool as amateur. |
| Persistent C2 / beacon implants                      | That's what Sliver/Mythic/Cobalt Strike are for, under a different SOW clause. |
| Credential brute-forcing inside verification         | Separate Hydra workflow, separate gate.                              |
| Self-propagating exploits across discovered subdomains | Scope creep is how engagements turn into CFAA cases.                |
| Memory-resident loaders / dropper chains             | Out of scope. Use the right tool.                                    |
| "Just one PHP shell on critical findings"            | See the entire rest of this document.                                |

If a customer asks for any of these, the right answer is *"that lives in
the operator's other toolkit, not in HunterPy."* HunterPy is the
recon + verification layer; the post-exploitation layer is somebody
else's problem (correctly).

---

## Compliance posture

- **BUSL-1.1** still applies. Verification doesn't change the licence.
- The signed authorization file is a *technical control*. It does **not**
  replace a signed SOW / engagement letter. The two layers reinforce
  each other.
- The `X-HunterPy-Verify: <uuid>` header on every verification request
  exists so blue teams can identify HunterPy traffic in logs. Don't
  strip it.
- Evidence bundles are designed to be the artifact you hand to the
  customer along with the report. They're self-contained and timestamped.

---

## FAQ

**Q: Why isn't there an "auto-verify on detection" mode?**
Because authorization is a *per-probe* decision: the authorization file
caps the safety level, but the operator should still see what's about
to fire before it does. `--verify-non-interactive` exists for CI; even
then, the auth file's `expires_at` and `hostnames` enforce scope.

**Q: Why limit to 50 findings per scan by default?**
A large scan can produce hundreds of INTERESTING findings. Verifying
all of them produces noise the SOC will treat as an attack. Tune
`--verify-max-findings` upward if your SOW allows.

**Q: What happens if a probe panics?**
The verifier catches the exception, records it as `status: error` with
the exception message in `error`, and continues. The crash is logged
under `<output>/logs/`.

**Q: Why HMAC and not asymmetric signatures?**
Single-operator workstations don't need a PKI. If your firm wants
per-operator key rotation, set `$HUNTERPY_AUTH_KEY` to a per-engagement
key derived from your secrets manager.
