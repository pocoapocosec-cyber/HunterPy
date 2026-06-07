"""Tests for the PoC generator and impact analyzer."""
import unittest

from reporting.impact_analyzer import ImpactAnalyzer
from reporting.poc_generator import PoC, PoCGenerator


class TestPoCGenerator(unittest.TestCase):
    def setUp(self):
        self.gen = PoCGenerator()

    def test_git_exposed_has_curl_step(self):
        p = self.gen.generate({
            "type": "git_exposed",
            "url": "https://x.com/.git/HEAD",
        })
        self.assertIsInstance(p, PoC)
        self.assertTrue(any("curl" in s.lower() for s in p.steps))
        self.assertIn("git", p.remediation.lower())

    def test_env_exposed_includes_rotation_advice(self):
        p = self.gen.generate({
            "type": "env_exposed",
            "url": "https://x.com/.env",
        })
        self.assertTrue(any("rotate" in s.lower() for s in p.steps))

    def test_unknown_type_falls_back_generic(self):
        p = self.gen.generate({"type": "mystery_thing", "url": "https://x.com"})
        self.assertEqual(p.finding_type, "mystery_thing")
        self.assertTrue(p.steps)            # generic builder always returns steps

    def test_cve_includes_fixed_versions_when_available(self):
        p = self.gen.generate({
            "type": "cve", "url": "x",
            "evidence": {"cve_id": "CVE-2024-1234",
                         "product": "apache", "version": "2.4.49",
                         "fixed_versions": ["2.4.51", "2.4.52"]},
        })
        self.assertIn("CVE-2024-1234", p.title)
        joined = " ".join(p.steps)
        self.assertIn("2.4.51", joined)

    def test_no_payloads_leak(self):
        # PoC text must never contain a working XSS/SQLi payload
        for ftype in ("git_exposed", "env_exposed", "admin_panel",
                      "weak_csp", "cors_wildcard"):
            p = self.gen.generate({"type": ftype, "url": "https://x"})
            joined = (p.description + " " + " ".join(p.steps)
                      + " " + (p.sample_command or "")).lower()
            self.assertNotIn("<script>alert", joined)
            self.assertNotIn("' or 1=1", joined)


class TestImpactAnalyzer(unittest.TestCase):
    def setUp(self):
        self.a = ImpactAnalyzer()

    def test_critical_maps_to_p1(self):
        s = self.a.analyze({"severity": "CRITICAL", "type": "env_exposed",
                            "classification": "INTERESTING"})
        self.assertEqual(s.priority_tier, "P1")
        self.assertIn("PCI-DSS", s.compliance_hints)

    def test_low_severity_interesting_gets_promoted(self):
        # MEDIUM severity but classifier says INTERESTING → promoted to P2
        s = self.a.analyze({"severity": "MEDIUM",
                            "type": "cors_reflection",
                            "classification": "INTERESTING"})
        self.assertEqual(s.priority_tier, "P2")

    def test_info_severity_stays_p4(self):
        s = self.a.analyze({"severity": "INFO", "type": "endpoint_discovered",
                            "classification": "COMMON"})
        self.assertEqual(s.priority_tier, "P4")

    def test_no_dollar_figures_anywhere(self):
        # Honest tool — never invent monetary estimates
        s = self.a.analyze({"severity": "CRITICAL", "type": "git_exposed"})
        blob = s.rationale + " " + s.suggested_sla + " " + s.data_at_risk
        for needle in ("$", "USD", "EUR", "GBP", "dollars", "millions"):
            self.assertNotIn(needle, blob)


if __name__ == "__main__":
    unittest.main()
