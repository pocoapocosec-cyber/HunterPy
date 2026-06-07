"""Tests for the evidence-bundle writer + redaction."""
from __future__ import annotations

import json
import os
import re
import tempfile
import unittest

from modules.exploit.evidence import EvidenceBundle, _redact, safe_filename
from modules.exploit.results import (
    HttpExchange, SafetyLevel, VerificationResult, VerificationStatus,
)


class RedactionTests(unittest.TestCase):
    def test_app_secret_value_is_hashed_out(self):
        text = "APP_SECRET=hunter2supersecretvalue\nFOO=bar"
        out = _redact(text)
        self.assertNotIn("hunter2supersecretvalue", out)
        self.assertIn("APP_SECRET", out)
        self.assertIn("REDACTED-sha256:", out)

    def test_database_url_is_hashed_out(self):
        text = 'DATABASE_URL="mysql://root:p@ssw0rd@db/foo"'
        out = _redact(text)
        self.assertNotIn("p@ssw0rd", out)
        self.assertIn("DATABASE_URL", out)

    def test_aws_access_key_pattern_redacted(self):
        text = "credential AKIAIOSFODNN7EXAMPLE in script"
        out = _redact(text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)

    def test_empty_input_is_safe(self):
        self.assertEqual(_redact(""), "")
        self.assertEqual(_redact(None), None)


class SafeFilenameTests(unittest.TestCase):
    def test_strips_dangerous_chars(self):
        self.assertEqual(safe_filename("../../etc/passwd"), "_.._.._etc_passwd")
        self.assertEqual(safe_filename("good-name_1.txt"), "good-name_1.txt")

    def test_caps_length(self):
        long = "a" * 500
        self.assertLessEqual(len(safe_filename(long)), 120)

    def test_empty_falls_back(self):
        self.assertEqual(safe_filename(""), "unnamed")


class EvidenceBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _result(self):
        ex = HttpExchange(
            method="GET",
            url="https://example.com/_profiler/phpinfo",
            request_headers={"X-HunterPy-Verify": "hpv-abc",
                              "User-Agent": "test"},
            response_status=200,
            response_headers={"Content-Type": "text/html"},
            response_body_preview="PHP Version 5.6.40 APP_SECRET=topsecretvalue",
            response_body_sha256="deadbeef",
            elapsed_ms=42,
        )
        return VerificationResult(
            finding_uid="sf_phpinfo_001",
            finding_type="symfony_profiler_phpinfo",
            probe_name="symfony_profiler_phpinfo",
            safety_level=SafetyLevel.READ_ONLY,
            status=VerificationStatus.CONFIRMED,
            summary="phpinfo exposed",
            proof="leaked keys: ['APP_SECRET']; php_version=5.6.40",
            exchanges=[ex],
            operator_consent_marker="hpv-abc",
        )

    def test_writes_full_bundle_structure(self):
        bundle = EvidenceBundle(self.tmp.name, "sf_phpinfo_001")
        path = bundle.write_result(self._result(),
                                    authorization={"engagement": "t"})
        self.assertTrue(os.path.exists(path))
        self.assertTrue(os.path.exists(
            os.path.join(bundle.dir, "exchanges", "000.http")))
        self.assertTrue(os.path.exists(os.path.join(bundle.dir, "proof.txt")))
        self.assertTrue(os.path.exists(
            os.path.join(bundle.dir, "authorization.json")))

    def test_exchange_file_redacts_secret(self):
        bundle = EvidenceBundle(self.tmp.name, "sf_phpinfo_001")
        bundle.write_result(self._result())
        ex_path = os.path.join(bundle.dir, "exchanges", "000.http")
        with open(ex_path) as f:
            content = f.read()
        self.assertNotIn("topsecretvalue", content)
        self.assertIn("REDACTED-sha256:", content)

    def test_result_json_redacts_secret(self):
        bundle = EvidenceBundle(self.tmp.name, "sf_phpinfo_001")
        bundle.write_result(self._result())
        result_path = os.path.join(bundle.dir, "result.json")
        with open(result_path) as f:
            data = json.load(f)
        body = data["exchanges"][0]["response_body_preview"]
        self.assertNotIn("topsecretvalue", body)

    def test_result_json_roundtrips_status_as_string(self):
        bundle = EvidenceBundle(self.tmp.name, "sf_phpinfo_001")
        bundle.write_result(self._result())
        with open(os.path.join(bundle.dir, "result.json")) as f:
            data = json.load(f)
        self.assertEqual(data["status"], "confirmed")
        self.assertEqual(data["safety_level"], "read_only")


if __name__ == "__main__":
    unittest.main()
