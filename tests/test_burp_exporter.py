"""Tests for the Burp Suite XML exporter (no network, no Burp install)."""
import unittest
import xml.etree.ElementTree as ET

from reporting.burp_exporter import (
    _stable_type_code,
    _split_url,
    export_findings_to_burp_xml,
)


class TestUrlSplit(unittest.TestCase):
    def test_full_url(self):
        r = _split_url("https://example.com/login?next=/x")
        self.assertEqual(r["host_url"], "https://example.com")
        self.assertEqual(r["path"], "/login?next=/x")

    def test_bare_host_fallback(self):
        r = _split_url("example.com")
        # No scheme → host_url == input, path defaults to "/"
        self.assertEqual(r["path"], "/")

    def test_empty(self):
        r = _split_url("")
        self.assertEqual(r["path"], "/")


class TestTypeCode(unittest.TestCase):
    def test_deterministic(self):
        a = _stable_type_code("sql_injection")
        b = _stable_type_code("sql_injection")
        self.assertEqual(a, b)

    def test_different_types_differ(self):
        self.assertNotEqual(
            _stable_type_code("sql_injection"),
            _stable_type_code("env_exposed"),
        )

    def test_format(self):
        code = _stable_type_code("anything")
        self.assertTrue(code.startswith("0x"))
        # Must be 10 chars total (0x + 8 hex digits) and parse as int
        self.assertEqual(len(code), 10)
        self.assertGreater(int(code, 16), 0x08000000)


class TestXmlExport(unittest.TestCase):
    def setUp(self):
        self.findings = [
            {
                "id": "F1",
                "module": "headers",
                "type": "missing_security_header",
                "title": "Missing CSP",
                "description": "No Content-Security-Policy header.",
                "url": "https://example.com/",
                "severity": "MEDIUM",
                "classification": "COMMON",
                "classification_reason": "known common type",
            },
            {
                "id": "F2",
                "module": "surface",
                "type": "git_exposed",
                "title": "Exposed .git/HEAD",
                "description": "The .git directory is publicly reachable.",
                "url": "https://dev.example.com/.git/HEAD",
                "severity": "CRITICAL",
                "classification": "INTERESTING",
                "confirmed": True,
                "evidence": {"status": 200, "size": 41},
            },
        ]

    def test_export_produces_valid_xml(self):
        xml = export_findings_to_burp_xml(self.findings)
        root = ET.fromstring(xml)
        self.assertEqual(root.tag, "issues")
        self.assertEqual(len(root.findall("issue")), 2)

    def test_severity_mapped_correctly(self):
        xml = export_findings_to_burp_xml(self.findings)
        root = ET.fromstring(xml)
        sevs = [i.findtext("severity") for i in root.findall("issue")]
        self.assertEqual(sevs, ["Medium", "High"])
        # Burp accepts exactly these:
        for s in sevs:
            self.assertIn(s, ("High", "Medium", "Low", "Information", "False positive"))

    def test_confidence_from_tier(self):
        xml = export_findings_to_burp_xml(self.findings)
        root = ET.fromstring(xml)
        confs = [i.findtext("confidence") for i in root.findall("issue")]
        # COMMON → Tentative, INTERESTING → Firm
        self.assertEqual(confs, ["Tentative", "Firm"])

    def test_host_and_path_split(self):
        xml = export_findings_to_burp_xml(self.findings)
        root = ET.fromstring(xml)
        issues = root.findall("issue")
        self.assertEqual(issues[0].findtext("host"), "https://example.com")
        self.assertEqual(issues[0].findtext("path"), "/")
        self.assertEqual(issues[1].findtext("host"), "https://dev.example.com")
        self.assertEqual(issues[1].findtext("path"), "/.git/HEAD")

    def test_request_response_present(self):
        xml = export_findings_to_burp_xml(self.findings)
        root = ET.fromstring(xml)
        for issue in root.findall("issue"):
            rr = issue.find("requestresponse")
            self.assertIsNotNone(rr)
            self.assertIsNotNone(rr.find("request"))
            self.assertIsNotNone(rr.find("response"))

    def test_cdata_escapes_nested_cdata(self):
        # Don't let a malicious finding break our CDATA wrappers
        nasty = [{
            "id": "F3", "module": "x", "type": "x",
            "title": "Has ]]> inside",
            "description": "before ]]> after",
            "url": "https://x.com/",
            "severity": "LOW", "classification": "COMMON",
        }]
        xml = export_findings_to_burp_xml(nasty)
        # Must still parse
        root = ET.fromstring(xml)
        self.assertEqual(len(root.findall("issue")), 1)

    def test_includes_poc_when_provided(self):
        from reporting.poc_generator import _finding_key, PoC
        poc = PoC(
            title="Verify git exposure",
            finding_type="git_exposed",
            description="The .git directory leaks source.",
            steps=["1. curl https://dev.example.com/.git/HEAD"],
            sample_command="curl -sI https://dev.example.com/.git/HEAD",
            remediation="Block .git/ at the web server.",
            references=["https://owasp.org/x"],
        )
        pocs = {_finding_key(self.findings[1]): poc}
        xml = export_findings_to_burp_xml(self.findings, pocs=pocs)
        root = ET.fromstring(xml)
        git_issue = root.findall("issue")[1]
        detail = git_issue.findtext("issueDetail") or ""
        rem    = git_issue.findtext("remediationBackground") or ""
        self.assertIn("curl", detail)
        self.assertIn("Block .git", rem)

    def test_root_attributes(self):
        xml = export_findings_to_burp_xml(self.findings, burp_version="2024.99")
        root = ET.fromstring(xml)
        self.assertEqual(root.attrib.get("burpVersion"), "2024.99")
        self.assertTrue(root.attrib.get("exportTime"))

    def test_empty_findings_list(self):
        xml = export_findings_to_burp_xml([])
        root = ET.fromstring(xml)
        self.assertEqual(len(root.findall("issue")), 0)


if __name__ == "__main__":
    unittest.main()
