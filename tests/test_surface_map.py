"""Tests for SurfaceMap parsing helpers (no network)."""
from __future__ import annotations

import tempfile
import unittest
import unittest.mock
from argparse import Namespace

from config.settings import Settings
from modules.custom.surface_map import SurfaceMap


def _settings():
    ns = Namespace(target="example.com", target_list=None, scope=None,
                   mode="passive", modules=None, threads=2, timeout=5,
                   rate_limit=5, delay=0.1, auth_url=None,
                   username=None, username_list=None, password_list=None,
                   proxy=None, user_agent=None, cookies=None,
                   output=tempfile.mkdtemp(), format="md", verbose=False,
                   no_color=False, headers=None,
                   no_nvd=True, nvd_offline=True, nvd_api_key=None)
    return Settings(ns)


class TestExtractLinks(unittest.TestCase):
    def test_separates_internal_external(self):
        s = SurfaceMap(_settings())
        html = ('<a href="/a">a</a>'
                '<a href="https://example.com/b">b</a>'
                '<a href="https://other.com/c">c</a>'
                '<a href="https://sub.example.com/d">d</a>')
        internal, external = s.extract_links(html, "https://example.com/")
        self.assertIn("https://example.com/a", internal)
        self.assertIn("https://example.com/b", internal)
        self.assertIn("https://sub.example.com/d", internal)
        self.assertIn("https://other.com/c", external)

    def test_dedupes(self):
        s = SurfaceMap(_settings())
        html = '<a href="/x">1</a><a href="/x">2</a>'
        internal, _ = s.extract_links(html, "https://example.com/")
        self.assertEqual(internal, ["https://example.com/x"])

    def test_empty_html_safe(self):
        s = SurfaceMap(_settings())
        self.assertEqual(s.extract_links("", "https://x.com/"), ([], []))


class TestExtractForms(unittest.TestCase):
    def test_basic_form(self):
        s = SurfaceMap(_settings())
        html = ('<form action="/submit" method="POST">'
                '<input type="text" name="user"/>'
                '<input type="password" name="pw"/>'
                '<input type="hidden" name="csrf" value="abc"/>'
                '</form>')
        forms = s.extract_forms(html)
        self.assertEqual(len(forms), 1)
        f = forms[0]
        self.assertEqual(f["method"], "POST")
        self.assertTrue(any(i["type"] == "password" for i in f["fields"]))
        self.assertTrue(any(i["hidden"] for i in f["fields"]))

    def test_regex_fallback_when_no_bs4(self):
        """When bs4 isn't available we fall back to a regex parser.
        Previously that fallback wrapped form bodies as `<form {body}</form>`
        which is invalid HTML and lost the action/method attrs entirely."""
        import modules.custom.surface_map as sm
        s = SurfaceMap(_settings())
        html = ('<form action="/login" method="POST">'
                '<input type="text" name="user"/>'
                '<input type="password" name="pw"/>'
                '</form>')
        with unittest.mock.patch.object(sm, "_HAVE_BS", False):
            forms = s.extract_forms(html)
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["method"], "POST")
        # The action url is normalized via urljoin against self.target
        self.assertTrue(forms[0]["action"].endswith("/login"))
        names = {f["name"] for f in forms[0]["fields"]}
        self.assertEqual(names, {"user", "pw"})


class TestExtractSubdomains(unittest.TestCase):
    def test_lstrip_bug_does_not_apply_to_web_prefix(self):
        """`str.lstrip('www.')` historically chewed leading w/. characters
        from any hostname starting with one. Verify the new prefix-check
        treats `web.example.com` correctly."""
        ns = unittest.mock.MagicMock(target="https://web.example.com",
            target_list=None, scope=None, mode="passive", modules=None,
            threads=2, timeout=5, rate_limit=5, delay=0.1, auth_url=None,
            username=None, username_list=None, password_list=None,
            proxy=None, user_agent=None, cookies=None,
            output=tempfile.mkdtemp(), format="md", verbose=False,
            no_color=False, headers=None, no_nvd=True, nvd_offline=True,
            nvd_api_key=None,
            dorks_active=False, confirm_dork_scraping=False,
            dork_max_queries=5, dork_max_results=10,
            dork_templates=None, dork_extra="")
        s = SurfaceMap(Settings(ns))
        # Sanity: regex finds api.web.example.com because base = web.example.com
        html = '<a href="https://api.web.example.com/v1">x</a>'
        out = s.extract_subdomains(html)
        # api.web.example.com is a sub of web.example.com → should match
        self.assertIn("api.web.example.com", out)


class TestExtractParams(unittest.TestCase):
    def test_deduped_param_names(self):
        out = SurfaceMap.extract_url_params([
            "https://x.com/?id=1&page=2",
            "https://x.com/search?q=hi&page=3",
            "https://x.com/other",
        ])
        self.assertEqual(sorted(out), ["id", "page", "q"])


if __name__ == "__main__":
    unittest.main()
