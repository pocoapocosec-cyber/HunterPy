"""Tests for the standalone PoC reproducer writer."""
from __future__ import annotations

import os
import stat
import tempfile
import unittest

from modules.exploit.poc_writer import write_poc_bundle


def _confirmed_result(**overrides):
    base = {
        "finding_uid":   "sf_phpinfo_001",
        "finding_type":  "symfony_profiler_phpinfo",
        "probe_name":    "symfony_profiler_phpinfo",
        "status":        "confirmed",
        "summary":       "phpinfo() exposed; leaked APP_SECRET",
        "proof":         "leaked keys: ['APP_SECRET']; php_version=5.6.40",
        "operator_consent_marker": "hpv-abc123def456",
        "exchanges": [{
            "method": "GET",
            "url":    "https://example.com/_profiler/phpinfo",
            "request_headers": {
                "X-HunterPy-Verify": "hpv-abc123def456",
                "User-Agent":        "HunterPy/2.0 (+authorized-testing)",
            },
            "request_body": None,
            "response_status": 200,
        }],
    }
    base.update(overrides)
    return base


def _finding(**kw):
    base = {"uid": "sf_phpinfo_001", "type": "symfony_profiler_phpinfo",
            "url": "https://example.com/_profiler/phpinfo",
            "severity": "CRITICAL"}
    base.update(kw)
    return base


def _auth():
    return {"engagement": "Acme/Q2-2026", "operator": "you@firm.example",
            "expires_at": "2026-07-01T00:00:00+00:00",
            "hostnames": ["example.com"],
            "max_safety_level": "trivial_write"}


class WritePocBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_writes_three_files_for_confirmed(self):
        written = write_poc_bundle(
            evidence_dir=self.tmp.name,
            finding_uid="sf_phpinfo_001",
            finding=_finding(),
            verification_result=_confirmed_result(),
            authorization=_auth(),
        )
        names = {os.path.basename(p) for p in written}
        self.assertEqual(names, {"poc.sh", "poc.py", "poc.md"})

    def test_skips_when_status_is_not_confirmed(self):
        for status in ("inconclusive", "safe_failed", "skipped", "error"):
            written = write_poc_bundle(
                evidence_dir=self.tmp.name,
                finding_uid=f"x_{status}",
                finding=_finding(),
                verification_result=_confirmed_result(status=status),
                authorization=_auth(),
            )
            self.assertEqual(written, [],
                              f"poc should NOT be written for status={status}")

    def test_skips_when_no_exchanges_recorded(self):
        result = _confirmed_result()
        result["exchanges"] = []
        written = write_poc_bundle(
            evidence_dir=self.tmp.name, finding_uid="no_ex",
            finding=_finding(), verification_result=result,
            authorization=_auth())
        self.assertEqual(written, [])

    def test_bash_script_is_executable(self):
        written = write_poc_bundle(
            evidence_dir=self.tmp.name, finding_uid="sf_phpinfo_001",
            finding=_finding(),
            verification_result=_confirmed_result(),
            authorization=_auth())
        sh = next(p for p in written if p.endswith("poc.sh"))
        mode = os.stat(sh).st_mode
        self.assertTrue(mode & stat.S_IXUSR, "poc.sh must be executable")
        # Mode 0700 — owner-only, no group/other access
        self.assertEqual(mode & 0o777, 0o700)

    def test_python_script_is_executable_and_uses_stdlib_only(self):
        written = write_poc_bundle(
            evidence_dir=self.tmp.name, finding_uid="sf_phpinfo_001",
            finding=_finding(),
            verification_result=_confirmed_result(),
            authorization=_auth())
        py = next(p for p in written if p.endswith("poc.py"))
        self.assertEqual(os.stat(py).st_mode & 0o777, 0o700)
        with open(py) as f:
            content = f.read()
        # urllib only — no `import requests`, no `import paramiko` etc.
        self.assertIn("import urllib.request", content)
        self.assertNotIn("import requests", content)

    def test_bash_includes_url_method_and_consent_header(self):
        written = write_poc_bundle(
            evidence_dir=self.tmp.name, finding_uid="sf_phpinfo_001",
            finding=_finding(),
            verification_result=_confirmed_result(),
            authorization=_auth())
        with open(next(p for p in written if p.endswith("poc.sh"))) as f:
            sh = f.read()
        self.assertIn("https://example.com/_profiler/phpinfo", sh)
        self.assertIn("X-HunterPy-Verify: hpv-abc123def456", sh)
        # Single curl invocation only — no loops, no retry storms
        self.assertEqual(sh.count("curl -"), 1)
        # No while/for loops
        self.assertNotIn("while ", sh)
        self.assertNotIn("for i in", sh)

    def test_bash_exit_codes_match_spec(self):
        """0 = still reproducible (fix NOT applied);
           1 = status diverged (fix MAY be in place);
           2 = network failure."""
        written = write_poc_bundle(
            evidence_dir=self.tmp.name, finding_uid="sf_phpinfo_001",
            finding=_finding(),
            verification_result=_confirmed_result(),
            authorization=_auth())
        with open(next(p for p in written if p.endswith("poc.sh"))) as f:
            sh = f.read()
        self.assertIn("exit 0", sh)
        self.assertIn("exit 1", sh)
        self.assertIn("exit 2", sh)

    def test_readme_documents_what_poc_will_NOT_do(self):
        written = write_poc_bundle(
            evidence_dir=self.tmp.name, finding_uid="sf_phpinfo_001",
            finding=_finding(),
            verification_result=_confirmed_result(),
            authorization=_auth())
        with open(next(p for p in written if p.endswith("poc.md"))) as f:
            md = f.read()
        # Must explicitly call out what the PoC WON'T do — that's the
        # whole point of the design.
        for must in ("webshell", "modify any persistent state", "pivot",
                     "fuzz"):
            self.assertIn(must, md, f"readme missing safety note: {must}")

    def test_readme_includes_authorization_context(self):
        written = write_poc_bundle(
            evidence_dir=self.tmp.name, finding_uid="sf_phpinfo_001",
            finding=_finding(),
            verification_result=_confirmed_result(),
            authorization=_auth())
        with open(next(p for p in written if p.endswith("poc.md"))) as f:
            md = f.read()
        self.assertIn("Acme/Q2-2026", md)
        self.assertIn("you@firm.example", md)
        self.assertIn("hpv-abc123def456", md)

    def test_no_credentials_or_secrets_leak_into_poc(self):
        # Probes record body previews that get redacted to SHA-256 in the
        # bundle. The PoC writer reproduces only the REQUEST, not the
        # response — but verify defensively that nothing leaks.
        result = _confirmed_result(
            proof="leaked APP_SECRET (hashed) and DATABASE_URL (hashed)")
        result["exchanges"][0]["response_body_preview"] = (
            "APP_SECRET=DO_NOT_LEAK_THIS_VALUE")
        written = write_poc_bundle(
            evidence_dir=self.tmp.name, finding_uid="sf_phpinfo_001",
            finding=_finding(), verification_result=result,
            authorization=_auth())
        for path in written:
            with open(path) as f:
                content = f.read()
            self.assertNotIn("DO_NOT_LEAK_THIS_VALUE", content,
                              f"secret leaked into {path}")


class VerifierIntegrationTests(unittest.TestCase):
    """The verifier must call write_poc_bundle when config.write_poc is on
    AND a probe returns CONFIRMED — and must NOT call it otherwise."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _run_one(self, write_poc, status):
        from types import SimpleNamespace
        from unittest.mock import patch
        from modules.exploit.authorization import create_authorization
        from modules.exploit.probes.base import Probe, register_probe
        from modules.exploit.results import SafetyLevel, VerificationStatus
        from modules.exploit.verifier import Verifier, VerifierConfig

        class _Probe(Probe):
            probe_name = "_test_poc_probe"
            safety_level = SafetyLevel.READ_ONLY
            def execute(_self):
                from modules.exploit.results import HttpExchange
                _self.exchanges.append(HttpExchange(
                    method="GET", url="https://example.com/x",
                    request_headers={"X-HunterPy-Verify": "hpv-x"},
                    response_status=200))
                return _self._new_result(
                    VerificationStatus(status), "ok",
                    proof="proven")

        register_probe("_test_poc_finding")(_Probe)
        auth = create_authorization(
            engagement="t", operator="op", hostnames=["example.com"],
            valid_days=1, max_safety_level="read_only", key=b"k" * 32)
        cfg = VerifierConfig(output_dir=self.tmp.name,
                              rate_limit_per_sec=1000.0,
                              non_interactive=True, write_poc=write_poc)
        v = Verifier(config=cfg, authorization=auth,
                     settings=SimpleNamespace(target="example.com", timeout=5))
        finding = {"type": "_test_poc_finding", "uid": "poc-001",
                   "classification": "INTERESTING",
                   "url": "https://example.com/x"}
        v.verify_findings([finding])
        return os.path.join(self.tmp.name, "verification", "poc-001")

    def test_poc_files_written_when_flag_on_and_confirmed(self):
        d = self._run_one(write_poc=True, status="confirmed")
        for name in ("poc.sh", "poc.py", "poc.md"):
            self.assertTrue(os.path.exists(os.path.join(d, name)),
                             f"missing {name}")

    def test_poc_files_NOT_written_when_flag_off(self):
        d = self._run_one(write_poc=False, status="confirmed")
        for name in ("poc.sh", "poc.py", "poc.md"):
            self.assertFalse(os.path.exists(os.path.join(d, name)),
                              f"{name} written despite write_poc=False")

    def test_poc_files_NOT_written_when_status_inconclusive(self):
        d = self._run_one(write_poc=True, status="inconclusive")
        for name in ("poc.sh", "poc.py", "poc.md"):
            self.assertFalse(os.path.exists(os.path.join(d, name)),
                              f"{name} written despite status=inconclusive")


if __name__ == "__main__":
    unittest.main()
