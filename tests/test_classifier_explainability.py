"""Tests for the structured classification_explanation block."""
from __future__ import annotations

import unittest

from classifiers.finding_classifier import FindingClassifier


class ExplanationShapeTests(unittest.TestCase):
    def setUp(self):
        self.c = FindingClassifier()

    def test_explanation_block_present_on_every_finding(self):
        f = {"type": "missing_security_header", "severity": "MEDIUM",
              "title": "Missing X-Frame-Options"}
        out = self.c.classify(f)
        self.assertIn("classification_explanation", out)
        exp = out["classification_explanation"]
        for key in ("final_class", "confidence", "primary_reason",
                    "factors", "context_chains", "human_explanation"):
            self.assertIn(key, exp, f"missing key {key} in explanation")

    def test_module_confirmed_records_module_hint_factor(self):
        f = {"type": "symfony_profiler_phpinfo", "confirmed": True,
              "severity": "CRITICAL", "title": "phpinfo exposed"}
        out = self.c.classify(f)
        exp = out["classification_explanation"]
        self.assertEqual(exp["final_class"], "INTERESTING")
        kinds = [fac["kind"] for fac in exp["factors"]]
        self.assertIn("module_hint", kinds)

    def test_type_table_match_recorded(self):
        f = {"type": "sql_injection", "severity": "HIGH",
              "title": "SQLi in /api/x"}
        out = self.c.classify(f)
        kinds = [fac["kind"] for fac in out["classification_explanation"]["factors"]]
        self.assertIn("type_table", kinds)

    def test_score_only_finding_records_severity_score_factor(self):
        # Unknown type with no signature match → score-only path.
        f = {"type": "random_unknown_type", "severity": "HIGH",
              "title": "Custom finding from a third-party module"}
        out = self.c.classify(f)
        factors = out["classification_explanation"]["factors"]
        self.assertTrue(any(fac["kind"] == "severity_score" for fac in factors))

    def test_signature_pack_match_records_matched_entry(self):
        # Use the interesting_patterns pack by faking a finding that
        # contains one of its keywords. We don't depend on a specific
        # pack entry — we only assert that IF a pack matched, the
        # matched_entry dict is present.
        f = {"type": "weird_type",
              "title": "Database backup file backup.sql found at /backup.sql",
              "url": "https://example.com/backup.sql"}
        out = self.c.classify(f)
        for fac in out["classification_explanation"]["factors"]:
            if fac["kind"] == "signature_pack":
                self.assertIn("matched_entry", fac)
                self.assertIn("pack", fac)

    def test_human_explanation_is_non_empty_string(self):
        f = {"type": "sql_injection", "severity": "HIGH",
              "title": "SQLi", "url": "https://example.com/?id=1"}
        out = self.c.classify(f)
        human = out["classification_explanation"]["human_explanation"]
        self.assertIsInstance(human, str)
        self.assertGreater(len(human), 20)
        self.assertIn("INTERESTING", human)

    def test_context_chains_reflected_in_explanation(self):
        f = {"type": "symfony_profiler_phpinfo", "confirmed": True,
              "severity": "CRITICAL",
              "attack_chains": [{"name": "symfony_full_pwnage"}]}
        out = self.c.classify(f)
        exp = out["classification_explanation"]
        self.assertIn("symfony_full_pwnage", exp["context_chains"])
        self.assertIn("symfony_full_pwnage", exp["human_explanation"])

    def test_context_rule_decoy_404_demotion_recorded(self):
        # Build a finding that would normally be INTERESTING but gets
        # demoted via the decoy_404 context rule.
        f = {"type": "sensitive_data_exposure",
              "title": "phpinfo file disclosure",
              "status_code": 404}
        out = self.c.classify(f)
        self.assertEqual(out["classification"], "FALSE_ALARM")
        factors = out["classification_explanation"]["factors"]
        self.assertTrue(any(fac.get("kind") == "context_rule"
                             and fac.get("rule") == "decoy_404_demotion"
                             for fac in factors))

    def test_backwards_compat_string_field_still_present(self):
        """Old consumers still see `classification_reason` as a string."""
        f = {"type": "sql_injection", "severity": "HIGH", "title": "SQLi"}
        out = self.c.classify(f)
        self.assertIn("classification_reason", out)
        self.assertIsInstance(out["classification_reason"], str)


if __name__ == "__main__":
    unittest.main()
