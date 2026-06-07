"""Tests for FindingClassifier and SeverityScorer."""
from __future__ import annotations

import unittest

from classifiers.finding_classifier import FindingClassifier
from classifiers.severity_scorer import SeverityScorer


class TestSeverityScorer(unittest.TestCase):
    def setUp(self):
        self.s = SeverityScorer()

    def test_critical_with_high_value_type(self):
        score = self.s.score({"severity": "CRITICAL", "type": "sql_injection"})
        self.assertGreaterEqual(score, 9.0)

    def test_info_scores_low(self):
        score = self.s.score({"severity": "INFO", "type": "robots_txt"})
        self.assertLess(score, 3.0)

    def test_admin_path_boost(self):
        score = self.s.score({"severity": "MEDIUM", "type": "directory_found",
                              "url": "https://x.com/admin"})
        self.assertGreater(score, 5.0)

    def test_cvss_boost(self):
        score = self.s.score({"severity": "MEDIUM", "type": "cve", "cvss": 9.8})
        self.assertGreaterEqual(score, 7.0)


class TestFindingClassifier(unittest.TestCase):
    def setUp(self):
        self.c = FindingClassifier()

    def test_confirmed_is_interesting(self):
        f = self.c.classify({"module": "sqlmap", "type": "sql_injection",
                             "confirmed": True, "severity": "CRITICAL"})
        self.assertEqual(f["classification"], "INTERESTING")
        self.assertGreater(f["classification_confidence"], 0.9)

    def test_likely_false_alarm(self):
        f = self.c.classify({"module": "sqlmap", "likely_false_alarm": True,
                             "type": "sql_injection_test", "severity": "INFO"})
        self.assertEqual(f["classification"], "FALSE_ALARM")

    def test_known_interesting_type(self):
        f = self.c.classify({"module": "custom", "type": "env_exposed",
                             "severity": "CRITICAL"})
        self.assertEqual(f["classification"], "INTERESTING")

    def test_known_false_alarm_type(self):
        f = self.c.classify({"module": "headers", "type": "x_xss_protection_missing",
                             "severity": "LOW"})
        self.assertEqual(f["classification"], "FALSE_ALARM")

    def test_medium_score_is_common(self):
        f = self.c.classify({"module": "headers", "type": "missing_security_header",
                             "severity": "MEDIUM",
                             "title": "Missing X-Frame-Options"})
        self.assertIn(f["classification"], ("COMMON", "INTERESTING"))

    def test_classify_all_preserves_count(self):
        items = [
            {"module": "a", "type": "x", "severity": "INFO"},
            {"module": "b", "type": "sql_injection", "confirmed": True, "severity": "CRITICAL"},
            {"module": "c", "type": "robots_txt", "severity": "INFO"},
        ]
        out = self.c.classify_all(items)
        self.assertEqual(len(out), 3)
        # all stamped
        for f in out:
            self.assertIn("classification", f)
            self.assertIn("priority", f)

    def test_summary_counts(self):
        items = self.c.classify_all([
            {"module": "x", "type": "env_exposed", "severity": "CRITICAL"},
            {"module": "y", "type": "missing_security_header", "severity": "MEDIUM",
             "title": "Missing CSP"},
            {"module": "z", "type": "robots_txt", "severity": "INFO"},
        ])
        s = self.c.summarize(items)
        self.assertEqual(s["total"], 3)
        self.assertEqual(
            s["interesting"] + s["common"] + s["false_alarms"], 3
        )


if __name__ == "__main__":
    unittest.main()
