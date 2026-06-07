"""Tests for the dork builder (no network)."""
import unittest

from modules.osint.dork_builder import DorkBuilder, Dork, DorkSet


class TestDorkBuilder(unittest.TestCase):
    def setUp(self):
        self.b = DorkBuilder()

    def test_templates_loaded(self):
        tpls = self.b.list_templates()
        self.assertTrue(tpls)
        names = {t["name"] for t in tpls}
        self.assertIn("exposed_config", names)
        self.assertIn("login_pages",    names)

    def test_build_substitutes_target(self):
        s = self.b.build("example.com")
        self.assertEqual(s.target, "example.com")
        self.assertTrue(s.dorks)
        for d in s.dorks:
            self.assertIn("example.com", d.query)
            self.assertIn("example.com", d.google_url)
            self.assertTrue(d.google_url.startswith("https://www.google.com/search?q="))

    def test_only_filter(self):
        s = self.b.build("x.com", only=["login_pages"])
        self.assertTrue(s.dorks)
        for d in s.dorks:
            self.assertEqual(d.template, "login_pages")

    def test_extra_keywords_appended(self):
        s = self.b.build("x.com", only=["login_pages"], extra_keywords="-staging")
        for d in s.dorks:
            self.assertTrue(d.query.endswith("-staging"))

    def test_empty_target(self):
        s = self.b.build("")
        self.assertEqual(s.dorks, [])

    def test_by_template_grouping(self):
        s = self.b.build("x.com")
        groups = s.by_template()
        self.assertIn("exposed_config", groups)
        self.assertTrue(all(isinstance(d, Dork) for d in groups["exposed_config"]))

    def test_to_dict_serializable(self):
        s = self.b.build("x.com", only=["bug_bounty_program"])
        d = s.to_dict()
        self.assertEqual(d["target"], "x.com")
        self.assertGreater(d["count"], 0)
        # Should be JSON-serializable
        import json
        json.dumps(d)

    def test_custom_dork(self):
        d = self.b.build_custom("x.com", "site:{target} foo bar")
        self.assertEqual(d.query, "site:x.com foo bar")
        self.assertEqual(d.template, "custom")

    def test_urls_are_proper_encoded(self):
        s = self.b.build("x.com", only=["exposed_config"])
        for d in s.dorks:
            # Spaces should be encoded
            self.assertNotIn(" ", d.google_url)
            self.assertIn("+", d.google_url)


if __name__ == "__main__":
    unittest.main()
