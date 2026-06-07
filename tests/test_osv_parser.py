"""Tests for OSV.dev parser helpers (no network)."""
import unittest

from modules.external.osv_client import OSVClient


class TestPackageExtraction(unittest.TestCase):
    def test_extracts_jquery_version(self):
        out = OSVClient.extract_packages_from_urls([
            "https://x.com/static/jquery-3.4.1.min.js",
        ])
        self.assertEqual(out, [("jquery", "3.4.1",
                                "https://x.com/static/jquery-3.4.1.min.js")])

    def test_extracts_from_at_syntax(self):
        out = OSVClient.extract_packages_from_urls([
            "https://cdn/lodash@4.17.10/lodash.min.js",
        ])
        self.assertEqual(out[0][:2], ("lodash", "4.17.10"))

    def test_ignores_non_versioned(self):
        out = OSVClient.extract_packages_from_urls([
            "https://x.com/app.bundle.js",
        ])
        self.assertEqual(out, [])

    def test_dedupes(self):
        out = OSVClient.extract_packages_from_urls([
            "https://x.com/jquery-3.4.1.min.js",
            "https://x.com/static/jquery-3.4.1.min.js",
        ])
        self.assertEqual(len(out), 1)


class TestVulnToFinding(unittest.TestCase):
    def test_extracts_cve_alias_and_cvss(self):
        vuln = {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "aliases": ["CVE-2024-12345"],
            "summary": "Prototype pollution in lodash",
            "details": "Long description...",
            "severity": [{"type": "CVSS_V3",
                          "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "references": [{"type": "WEB", "url": "https://github.com/x/y"}],
            "affected": [{"ranges": [{"events": [{"introduced": "0"},
                                                 {"fixed": "4.17.21"}]}]}],
        }
        f = OSVClient.vuln_to_finding(vuln, "lodash", "4.17.10", "https://x/lodash.js")
        self.assertEqual(f["type"], "cve")
        self.assertEqual(f["evidence"]["cve_id"], "CVE-2024-12345")
        self.assertEqual(f["evidence"]["fixed_versions"], ["4.17.21"])
        self.assertEqual(f["evidence"]["package"], "lodash")

    def test_handles_missing_severity(self):
        vuln = {"id": "GHSA-x", "summary": "x"}
        f = OSVClient.vuln_to_finding(vuln, "p", "1.0.0", "u")
        self.assertIn(f["severity"], ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"))

    def test_does_not_parse_cvss_version_as_score(self):
        """REGRESSION: OSV's severity[].score is a CVSS *vector string*
        like 'CVSS:3.1/AV:N/AC:L/...', not a numeric base score. The
        previous implementation did .split('/')[0].replace('CVSS:','')
        which produces '3.1' (the spec version) — definitely not the
        base score of the vulnerability.
        """
        vuln = {
            "id": "GHSA-test",
            "severity": [{"type": "CVSS_V3",
                          "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            # When database_specific.severity is provided, that's authoritative
            "database_specific": {"severity": "CRITICAL"},
        }
        f = OSVClient.vuln_to_finding(vuln, "lib", "1.0.0", "u")
        # We should use the qualitative label, not "3.1"
        self.assertEqual(f["severity"], "CRITICAL")
        # The numeric cvss field is an approximation only; must never
        # equal 3.1 (which was the spec version, not the score)
        self.assertNotEqual(f["cvss"], 3.1)
        # And the original vector string should be preserved in evidence
        self.assertIn("AV:N", f["evidence"]["cvss_vector"])

    def test_falls_back_to_vector_label_when_no_db_specific(self):
        vuln = {
            "id": "GHSA-test2",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        }
        f = OSVClient.vuln_to_finding(vuln, "lib", "1.0.0", "u")
        # No database_specific.severity → label is UNKNOWN (we don't
        # invent a number from the vector) and severity is INFO/UNKNOWN.
        # Critically: cvss must not be 3.0
        self.assertNotEqual(f["cvss"], 3.0)


if __name__ == "__main__":
    unittest.main()
