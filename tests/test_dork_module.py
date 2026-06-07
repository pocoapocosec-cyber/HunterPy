"""Tests for the HunterPy DorkModule wrapper (no network)."""
import tempfile
import unittest
from argparse import Namespace

from config.settings import Settings
from modules.osint.dork_module import DorkModule


def _settings(**over):
    base = dict(
        target="example.com", target_list=None, scope=None,
        mode="passive", modules=None, threads=2, timeout=5,
        rate_limit=5, delay=0.1, auth_url=None,
        username=None, username_list=None, password_list=None,
        proxy=None, user_agent=None, cookies=None,
        output=tempfile.mkdtemp(), format="json", verbose=False,
        no_color=False, headers=None,
        no_nvd=True, nvd_offline=True, nvd_api_key=None,
        dorks_active=False, confirm_dork_scraping=False,
        dork_max_queries=5, dork_max_results=10,
        dork_templates=None, dork_extra="",
    )
    base.update(over)
    return Settings(Namespace(**base))


class TestDorkModulePreview(unittest.TestCase):
    def test_preview_mode_emits_one_finding_per_template(self):
        m = DorkModule(_settings())
        res = m.run()
        findings = res["findings"]
        self.assertTrue(findings)
        types = {f["type"] for f in findings}
        # preview only — never dork_hit
        self.assertEqual(types, {"dork_suggestion"})

    def test_dork_set_in_artifact(self):
        m = DorkModule(_settings())
        res = m.run()
        self.assertIn("dorks", res)
        self.assertEqual(res["dorks"]["target"], "example.com")
        self.assertGreater(res["dorks"]["count"], 0)

    def test_findings_carry_evidence(self):
        m = DorkModule(_settings())
        res = m.run()
        f = res["findings"][0]
        self.assertIn("evidence", f)
        ev = f["evidence"]
        for key in ("template", "queries", "google_urls", "bing_urls"):
            self.assertIn(key, ev)
        self.assertEqual(ev["mode"], "preview")

    def test_only_templates_filter_via_settings(self):
        s = _settings()
        s.dork_templates = ["login_pages"]
        m = DorkModule(s)
        res = m.run()
        for f in res["findings"]:
            self.assertEqual(f["evidence"]["template"], "login_pages")

    def test_active_requires_both_flags(self):
        # active=True but confirm=False → should NOT scrape
        s = _settings(dorks_active=True, confirm_dork_scraping=False)
        m = DorkModule(s)
        res = m.run()
        # No dork_hit / dork_scrape_blocked because active didn't trigger
        types = {f["type"] for f in res["findings"]}
        self.assertNotIn("dork_hit", types)
        self.assertNotIn("dork_scrape_blocked", types)

    def test_target_with_scheme_normalized(self):
        s = _settings(target="https://example.com/")
        m = DorkModule(s)
        res = m.run()
        # Host extracted from URL
        self.assertEqual(res["dorks"]["target"], "example.com")


if __name__ == "__main__":
    unittest.main()
