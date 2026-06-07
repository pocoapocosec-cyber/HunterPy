"""Tests for the Verifier orchestrator."""
from __future__ import annotations

import os
import tempfile
import unittest
from types import SimpleNamespace
from typing import List

from modules.exploit.authorization import create_authorization
from modules.exploit.probes.base import (
    PROBE_REGISTRY, Probe, register_probe,
)
from modules.exploit.results import (
    HttpExchange, SafetyLevel, VerificationResult, VerificationStatus,
)
from modules.exploit.verifier import Verifier, VerifierConfig


KEY = b"a" * 32


# ---------------------------------------------------------------------------
# Reusable fake probes for the orchestrator tests. We register them under
# bespoke finding types so they don't collide with the real probes.
# ---------------------------------------------------------------------------
@register_probe("_test_confirmed")
class _ConfirmedProbe(Probe):
    probe_name = "_test_confirmed"
    safety_level = SafetyLevel.READ_ONLY

    def execute(self):
        return self._new_result(VerificationStatus.CONFIRMED, "ok",
                                 proof="proven")


@register_probe("_test_crashes")
class _CrashingProbe(Probe):
    probe_name = "_test_crashes"
    safety_level = SafetyLevel.READ_ONLY

    def execute(self):
        raise RuntimeError("boom")


@register_probe("_test_destructive")
class _DestructiveProbe(Probe):
    probe_name = "_test_destructive"
    safety_level = SafetyLevel.DESTRUCTIVE

    def execute(self):
        return self._new_result(VerificationStatus.CONFIRMED, "ok")


@register_probe("_test_waf_block")
class _WafBlockedProbe(Probe):
    probe_name = "_test_waf_block"
    safety_level = SafetyLevel.READ_ONLY

    def execute(self):
        self.exchanges.append(HttpExchange(
            method="GET", url="https://example.com/foo",
            response_status=429,
            response_body_preview="cloudflare: rate limited",
        ))
        return self._new_result(VerificationStatus.SAFE_FAILED, "blocked")


# ---------------------------------------------------------------------------
def _auth(hostnames=("example.com",), max_safety="trivial_write",
          allow_destructive=False):
    return create_authorization(
        engagement="t", operator="op", hostnames=list(hostnames),
        valid_days=1, max_safety_level=max_safety,
        allow_destructive=allow_destructive, key=KEY)


def _settings():
    return SimpleNamespace(target="example.com", timeout=5,
                            user_agent="test", cookies=None)


# ---------------------------------------------------------------------------
class VerifierBasicFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = VerifierConfig(output_dir=self.tmp.name,
                                   rate_limit_per_sec=1000.0,
                                   non_interactive=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_eligible_filter_picks_only_known_types(self):
        v = Verifier(config=self.cfg, authorization=_auth(),
                     settings=_settings())
        findings = [
            {"type": "_test_confirmed", "classification": "INTERESTING",
             "url": "https://example.com/foo"},
            {"type": "unknown_type", "classification": "INTERESTING",
             "url": "https://example.com/bar"},
            {"type": "_test_confirmed", "classification": "COMMON",
             "severity": "LOW", "url": "https://example.com/low"},
        ]
        results = v.verify_findings(findings)
        # Only the first matches (known type + INTERESTING).
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, VerificationStatus.CONFIRMED)

    def test_severity_critical_eligible_even_without_classification(self):
        v = Verifier(config=self.cfg, authorization=_auth(),
                     settings=_settings())
        findings = [{"type": "_test_confirmed", "severity": "CRITICAL",
                     "url": "https://example.com/x"}]
        results = v.verify_findings(findings)
        self.assertEqual(len(results), 1)

    def test_verification_attached_to_finding(self):
        v = Verifier(config=self.cfg, authorization=_auth(),
                     settings=_settings())
        finding = {"type": "_test_confirmed", "classification": "INTERESTING",
                   "url": "https://example.com/foo"}
        v.verify_findings([finding])
        self.assertIn("verification", finding)
        self.assertEqual(finding["verification"]["status"], "confirmed")

    def test_evidence_bundle_written(self):
        v = Verifier(config=self.cfg, authorization=_auth(),
                     settings=_settings())
        v.verify_findings([{"type": "_test_confirmed",
                            "classification": "INTERESTING",
                            "uid": "test-finding-001",
                            "url": "https://example.com/foo"}])
        path = os.path.join(self.tmp.name, "verification", "test-finding-001",
                             "result.json")
        self.assertTrue(os.path.exists(path),
                        f"evidence bundle missing at {path}")


class VerifierAuthorizationGuardrailTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = VerifierConfig(output_dir=self.tmp.name,
                                   rate_limit_per_sec=1000.0,
                                   non_interactive=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_out_of_scope_host_is_skipped(self):
        v = Verifier(config=self.cfg,
                     authorization=_auth(hostnames=("only-this.com",)),
                     settings=_settings())
        results = v.verify_findings([{"type": "_test_confirmed",
                                       "classification": "INTERESTING",
                                       "url": "https://evil.example.com/x"}])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, VerificationStatus.SKIPPED)
        self.assertIn("not in the authorization scope", results[0].summary)

    def test_destructive_probe_blocked_without_cli_opt_in(self):
        v = Verifier(config=self.cfg,
                     authorization=_auth(max_safety="destructive",
                                          allow_destructive=True),
                     settings=_settings())
        # cli flag NOT set
        self.assertFalse(self.cfg.allow_destructive)
        results = v.verify_findings([{"type": "_test_destructive",
                                       "classification": "INTERESTING",
                                       "url": "https://example.com/x"}])
        self.assertEqual(results[0].status, VerificationStatus.SKIPPED)

    def test_destructive_probe_blocked_without_auth_opt_in(self):
        # CLI says ok, but auth file doesn't allow destructive
        cfg = VerifierConfig(output_dir=self.tmp.name,
                              rate_limit_per_sec=1000.0,
                              non_interactive=True,
                              allow_destructive=True)
        v = Verifier(config=cfg, authorization=_auth(max_safety="trivial_write"),
                     settings=_settings())
        results = v.verify_findings([{"type": "_test_destructive",
                                       "classification": "INTERESTING",
                                       "url": "https://example.com/x"}])
        self.assertEqual(results[0].status, VerificationStatus.SKIPPED)


class VerifierErrorHandlingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = VerifierConfig(output_dir=self.tmp.name,
                                   rate_limit_per_sec=1000.0,
                                   non_interactive=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_probe_crash_is_caught_and_recorded(self):
        v = Verifier(config=self.cfg, authorization=_auth(),
                     settings=_settings())
        results = v.verify_findings([{"type": "_test_crashes",
                                       "classification": "INTERESTING",
                                       "url": "https://example.com/x"}])
        self.assertEqual(results[0].status, VerificationStatus.ERROR)
        self.assertIn("boom", results[0].error or "")

    def test_waf_block_aborts_phase(self):
        v = Verifier(config=self.cfg, authorization=_auth(),
                     settings=_settings())
        findings = [
            {"type": "_test_waf_block", "classification": "INTERESTING",
             "url": "https://example.com/a"},
            {"type": "_test_confirmed", "classification": "INTERESTING",
             "url": "https://example.com/b"},
        ]
        results = v.verify_findings(findings)
        # Only the first ran; the second was aborted due to WAF backoff.
        self.assertEqual(len(results), 1)


class VerifierInteractivePromptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _make(self, answers: List[str]):
        it = iter(answers)
        return VerifierConfig(
            output_dir=self.tmp.name,
            rate_limit_per_sec=1000.0,
            non_interactive=False,
            confirm_prompt=lambda _: next(it),
        )

    def test_no_skips_finding(self):
        cfg = self._make(["n", "n"])
        v = Verifier(config=cfg, authorization=_auth(), settings=_settings())
        findings = [
            {"type": "_test_confirmed", "classification": "INTERESTING",
             "url": "https://example.com/a"},
            {"type": "_test_confirmed", "classification": "INTERESTING",
             "url": "https://example.com/b"},
        ]
        results = v.verify_findings(findings)
        self.assertEqual(len(results), 0)

    def test_quit_aborts_phase(self):
        cfg = self._make(["q"])
        v = Verifier(config=cfg, authorization=_auth(), settings=_settings())
        findings = [
            {"type": "_test_confirmed", "classification": "INTERESTING",
             "url": "https://example.com/a"},
            {"type": "_test_confirmed", "classification": "INTERESTING",
             "url": "https://example.com/b"},
        ]
        results = v.verify_findings(findings)
        self.assertEqual(len(results), 0)

    def test_all_runs_remaining(self):
        # First "a" should make every subsequent finding auto-run
        cfg = self._make(["a"])
        v = Verifier(config=cfg, authorization=_auth(), settings=_settings())
        findings = [
            {"type": "_test_confirmed", "classification": "INTERESTING",
             "url": "https://example.com/a"},
            {"type": "_test_confirmed", "classification": "INTERESTING",
             "url": "https://example.com/b"},
            {"type": "_test_confirmed", "classification": "INTERESTING",
             "url": "https://example.com/c"},
        ]
        results = v.verify_findings(findings)
        self.assertEqual(len(results), 3)
        for r in results:
            self.assertEqual(r.status, VerificationStatus.CONFIRMED)


class VerifierLimitsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_max_findings_cap_is_respected(self):
        cfg = VerifierConfig(output_dir=self.tmp.name,
                              rate_limit_per_sec=1000.0,
                              non_interactive=True,
                              max_findings=2)
        v = Verifier(config=cfg, authorization=_auth(), settings=_settings())
        findings = [{"type": "_test_confirmed", "classification": "INTERESTING",
                     "url": f"https://example.com/{i}"} for i in range(10)]
        results = v.verify_findings(findings)
        self.assertEqual(len(results), 2)

    def test_only_types_filter(self):
        cfg = VerifierConfig(output_dir=self.tmp.name,
                              rate_limit_per_sec=1000.0,
                              non_interactive=True,
                              only_types=["_test_confirmed"])
        v = Verifier(config=cfg, authorization=_auth(), settings=_settings())
        findings = [
            {"type": "_test_confirmed", "classification": "INTERESTING",
             "url": "https://example.com/a"},
            {"type": "_test_crashes", "classification": "INTERESTING",
             "url": "https://example.com/b"},
        ]
        results = v.verify_findings(findings)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].finding_type, "_test_confirmed")


if __name__ == "__main__":
    unittest.main()
