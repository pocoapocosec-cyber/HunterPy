"""Tests for the AI-consumable Markdown report writer."""
from __future__ import annotations

import unittest

from core.markdown_report import build_findings_summary, render_markdown


class TestFindingsSummary(unittest.TestCase):
    def test_summary_flags_interesting(self):
        findings = [
            {"classification": "INTERESTING", "type": "git_exposed",
             "title": "Exposed .git"},
            {"classification": "COMMON", "type": "missing_security_header",
             "title": "Missing security header: CSP"},
        ]
        out = build_findings_summary(findings, {}, {}, [])
        joined = " ".join(out)
        self.assertIn("INTERESTING", joined)
        self.assertIn("Missing security headers", joined)

    def test_summary_flags_sensitive_paths(self):
        surface = {
            "sensitive_paths": [
                {"url": "https://x.com/.env", "status_code": 200, "has_content": True},
                {"url": "https://x.com/robots.txt", "status_code": 200, "has_content": True},
            ]
        }
        out = build_findings_summary([], surface, {}, [])
        joined = " ".join(out)
        self.assertIn("Sensitive paths reachable", joined)
        self.assertIn(".env", joined)

    def test_summary_flags_cookie_issues(self):
        cookies = [{"name": "sess", "httponly": False, "secure": False, "samesite": None}]
        out = build_findings_summary([], {}, {}, cookies)
        joined = " ".join(out)
        self.assertIn("Cookies missing", joined)
        self.assertIn("HttpOnly", joined)

    def test_summary_flags_js_keywords(self):
        js = {"sensitive_keyword_hits": [{"file": "x.js", "keyword": "api_key",
                                          "line": 10, "context": "..."}]}
        out = build_findings_summary([], {}, js, [])
        self.assertTrue(any("sensitive keyword" in s.lower() for s in out))

    def test_empty_inputs_returns_empty(self):
        self.assertEqual(build_findings_summary([], {}, {}, []), [])


class TestRenderMarkdown(unittest.TestCase):
    def setUp(self):
        self.meta = {"mode": "passive", "scan_id": 1,
                     "start_time": "2026-01-01T00:00:00Z",
                     "end_time":   "2026-01-01T00:01:00Z",
                     "duration":   "0m 60s",
                     "modules_run": ["headers", "dns"]}

    def test_renders_all_required_sections(self):
        md = render_markdown(
            target="example.com",
            metadata=self.meta,
            findings=[
                {"module": "headers", "type": "missing_security_header",
                 "title": "Missing security header: CSP", "severity": "HIGH",
                 "classification": "COMMON",
                 "classification_reason": "x", "classification_confidence": 0.7},
            ],
            recon={"headers": {"server": "nginx",
                               "x-frame-options": "SAMEORIGIN"}},
            surface={"internal_links": ["https://example.com/a"],
                     "external_links": [],
                     "subdomains": [],
                     "forms": [],
                     "url_params": ["q"],
                     "sensitive_paths": [
                         {"url": "https://example.com/.env",
                          "status_code": 404, "has_content": False}
                     ]},
            javascript={"first_party_scripts": ["https://example.com/a.js"],
                        "third_party_scripts": [],
                        "sensitive_keyword_hits": [],
                        "endpoints": ["/api/v1/users"]},
            dns_records={"a": ["1.2.3.4"], "mx": [], "ns": [],
                          "txt": ["v=spf1 -all"], "cname": None},
            whois_data={"registrar": "Acme", "org": "Example Inc"},
            cookies=[{"name": "session", "httponly": True, "secure": True,
                      "samesite": "Strict", "raw_attrs": ["HttpOnly", "Secure"]}],
        )
        # required sections, in order
        for section in (
            "# Reconnaissance Report — example.com",
            "## Legal Notice",
            "## How To Use This Report",
            "## Scan Metadata",
            "## Technology Stack",
            "## Security Header Audit",
            "## Cookie Security",
            "## DNS Records",
            "## WHOIS Information",
            "## Discovered Links",
            "## Forms Discovered",
            "## URL Parameters Found",
            "## Sensitive Path Check",
            "## JavaScript Analysis",
            "## Summary of Notable Findings",
            "## Next Steps",
        ):
            self.assertIn(section, md, f"missing section: {section!r}")

    def test_handles_empty_inputs_gracefully(self):
        md = render_markdown(target="x.com", metadata={}, findings=[])
        self.assertIn("Reconnaissance Report", md)
        self.assertIn("How To Use This Report", md)

    def test_section_ordering_is_stable(self):
        md = render_markdown(target="x.com", metadata={}, findings=[])
        legal  = md.index("## Legal Notice")
        how    = md.index("## How To Use This Report")
        meta   = md.index("## Scan Metadata")
        next_  = md.index("## Next Steps")
        self.assertLess(legal, how)
        self.assertLess(how, meta)
        self.assertLess(meta, next_)

    def test_no_raw_secrets_in_output(self):
        # JS hits use a "<redacted>" mask for long tokens
        from modules.custom.js_analyzer import JSAnalyzer
        from argparse import Namespace
        ns = Namespace(target="example.com", target_list=None, scope=None,
                       mode="passive", modules=None, threads=2, timeout=5,
                       rate_limit=5, delay=0.1, auth_url=None,
                       username=None, username_list=None, password_list=None,
                       proxy=None, user_agent=None, cookies=None,
                       output="/tmp/hpy_test", format="md", verbose=False,
                       no_color=False, headers=None,
                       no_nvd=True, nvd_offline=True, nvd_api_key=None)
        import os, tempfile
        ns.output = tempfile.mkdtemp()
        from config.settings import Settings
        analyzer = JSAnalyzer(Settings(ns))
        body = 'var k = "api_key=AKIAIOSFODNN7EXAMPLE12345678";'
        hits, _ = analyzer._analyze([("https://x.com/app.js", body)])
        self.assertEqual(len(hits), 1)
        # The 20-char-plus token must be redacted from context
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE12345678", hits[0]["context"])


if __name__ == "__main__":
    unittest.main()
