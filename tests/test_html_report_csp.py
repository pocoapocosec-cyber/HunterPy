"""Tests for the Content-Security-Policy meta tag on the HTML report."""
from __future__ import annotations

import base64
import hashlib
import re
import unittest

from reporting.interactive_html import render_interactive_html


def _render():
    return render_interactive_html(
        target="example.com",
        metadata={"scan_id": "x", "mode": "passive", "modules_run": ["headers"]},
        findings=[{"id": "f1", "type": "missing_security_header",
                    "severity": "MEDIUM", "classification": "COMMON",
                    "title": "Missing CSP", "url": "https://example.com/",
                    "score": 5.0}],
        pocs={},
        impacts={},
    )


class CSPTests(unittest.TestCase):
    def test_csp_meta_tag_present(self):
        html = _render()
        self.assertIn('http-equiv="Content-Security-Policy"', html)

    def test_csp_locks_default_src_to_none(self):
        html = _render()
        m = re.search(r'content="([^"]+)"', html)
        self.assertIsNotNone(m)
        csp = m.group(1)
        self.assertIn("default-src 'none'", csp)
        self.assertIn("connect-src 'none'", csp)
        self.assertIn("form-action 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("base-uri 'none'", csp)

    def test_csp_script_src_includes_sha256_hash(self):
        html = _render()
        m = re.search(r"script-src\s+'sha256-([A-Za-z0-9+/=]+)'", html)
        self.assertIsNotNone(m,
            "CSP must use a sha256 hash for the inline script, not 'unsafe-inline'")
        hash_b64 = m.group(1)
        # Hash should be 44 chars (base64 of 32-byte sha256)
        self.assertEqual(len(hash_b64), 44)

    def test_hash_actually_matches_the_inline_script(self):
        """If the inline script changes, the hash must change too —
        otherwise the report's CSP would break the script."""
        html = _render()
        # Extract the main script body (non-JSON one)
        m = re.search(
            r'<script(?![^>]*type\s*=\s*"application/json")[^>]*>(.*?)</script>',
            html, re.DOTALL)
        self.assertIsNotNone(m, "main inline script block not found")
        script_body = m.group(1)
        expected = base64.b64encode(
            hashlib.sha256(script_body.encode("utf-8")).digest()
        ).decode("ascii")

        m2 = re.search(r"script-src\s+'sha256-([A-Za-z0-9+/=]+)'", html)
        self.assertEqual(m2.group(1), expected,
                          "CSP hash does not match the inline script body — "
                          "the report would refuse to execute its JS")

    def test_data_blob_remains_unrestricted(self):
        """The application/json data block isn't subject to script-src
        but it must still be present and parseable."""
        html = _render()
        self.assertIn('<script id="data" type="application/json">', html)


if __name__ == "__main__":
    unittest.main()
