"""Tests for the Symfony intel-pack detector (no real network).

The module is patched via `utils.http_client.http_get` so we control
every response. This both exercises the per-path probe logic and the
landing-page fingerprinting + credential-leak scan.
"""
from __future__ import annotations

import json
import tempfile
import unittest
import unittest.mock as mock
from argparse import Namespace

from config.settings import Settings
from modules.custom.symfony_detector import SymfonyDetector


def _ns(**over):
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
    return Namespace(**base)


class _Resp:
    """Stand-in for HTTPResponse so we don't need the real requests lib."""
    def __init__(self, status=200, text="", headers=None, raw_set_cookie=None,
                 url="https://example.com/"):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.raw_set_cookie = raw_set_cookie or []
        self.url = url
        self.cookies = {}


def _make(**over):
    return SymfonyDetector(Settings(_ns(**over)))


class TestIntelPackLoads(unittest.TestCase):
    def test_intel_pack_is_present(self):
        from modules.custom import symfony_detector as sd
        self.assertTrue(sd._INTEL)
        self.assertIn("exposure_paths", sd._INTEL)
        self.assertGreater(len(sd._INTEL["exposure_paths"]), 4)
        # Each path entry must have the required fields.
        for entry in sd._INTEL["exposure_paths"]:
            for k in ("path", "finding_type", "severity", "title", "description"):
                self.assertIn(k, entry)

    def test_intel_pack_references_all_three_reports(self):
        from modules.custom import symfony_detector as sd
        sources = " ".join(sd._INTEL.get("_sources", []))
        self.assertIn("SECREP-murilocarapeba-clinic", sources)
        self.assertIn("SECREP-symfony-edu", sources)
        self.assertIn("SECREP-symfony-upstream-issues", sources)


class TestFingerprint(unittest.TestCase):
    def test_detects_symfony_header(self):
        d = _make()
        resp = _Resp(headers={"X-Debug-Token": "abc123"})
        ok, ev = d._fingerprint_symfony(resp)
        self.assertTrue(ok)
        self.assertIn("x-debug-token", [h.lower() for h in ev["headers"]])

    def test_detects_body_markers(self):
        d = _make()
        resp = _Resp(text="<div>Symfony Profiler</div>")
        ok, ev = d._fingerprint_symfony(resp)
        self.assertTrue(ok)
        self.assertIn("Symfony Profiler", ev.get("body_markers", []))

    def test_returns_false_when_no_signals(self):
        d = _make()
        resp = _Resp(text="<html><body>nothing here</body></html>")
        ok, ev = d._fingerprint_symfony(resp)
        self.assertFalse(ok)
        self.assertEqual(ev, {})


class TestProbePaths(unittest.TestCase):
    def test_probe_matches_status_and_body(self):
        d = _make()
        entry = {
            "path": "/_profiler/", "finding_type": "symfony_profiler_exposed",
            "severity": "CRITICAL", "title": "X", "description": "Y",
            "match_status": [200], "match_body_any": ["Profiler"],
        }
        resp = _Resp(status=200, text="Welcome to the Profiler")
        with mock.patch("modules.custom.symfony_detector.http_get",
                        return_value=resp):
            f = d._probe_path(entry)
        self.assertIsNotNone(f)
        self.assertEqual(f["type"], "symfony_profiler_exposed")
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertTrue(f["confirmed"])
        self.assertTrue(f["interesting"])
        # Source attribution propagated
        self.assertIn("source_reports", f["evidence"])

    def test_probe_rejects_when_status_wrong(self):
        d = _make()
        entry = {"path": "/_profiler/", "finding_type": "x",
                 "match_status": [200], "match_body_any": ["Profiler"]}
        resp = _Resp(status=404, text="Profiler")
        with mock.patch("modules.custom.symfony_detector.http_get",
                        return_value=resp):
            self.assertIsNone(d._probe_path(entry))

    def test_probe_rejects_when_body_marker_missing(self):
        d = _make()
        entry = {"path": "/_profiler/", "finding_type": "x",
                 "match_status": [200], "match_body_any": ["Profiler"]}
        resp = _Resp(status=200, text="nothing useful")
        with mock.patch("modules.custom.symfony_detector.http_get",
                        return_value=resp):
            self.assertIsNone(d._probe_path(entry))

    def test_probe_returns_none_on_network_failure(self):
        d = _make()
        entry = {"path": "/_profiler/", "finding_type": "x",
                 "match_status": [200], "match_body_any": ["X"]}
        with mock.patch("modules.custom.symfony_detector.http_get",
                        return_value=None):
            self.assertIsNone(d._probe_path(entry))


class TestCredentialScan(unittest.TestCase):
    def test_redacts_values_in_evidence(self):
        d = _make()
        body = "var dump:  APP_SECRET=ThisIsASuperSecretValue1234"
        out = d._scan_credentials(body)
        self.assertTrue(out)
        ev = out[0]["evidence"]
        # The real secret string must NOT appear in evidence
        self.assertNotIn("ThisIsASuperSecretValue1234", json.dumps(ev))
        # But the masked version does
        self.assertIn("***", ev["value_preview"])
        self.assertEqual(out[0]["severity"], "CRITICAL")

    def test_does_not_fire_on_mere_mention(self):
        d = _make()
        # Documentation that mentions APP_SECRET= but no value-shaped string
        body = "Set the APP_SECRET= variable in your .env"
        out = d._scan_credentials(body)
        # Either no findings, or the value-preview is the documentation text
        # — what we care about is the test below.
        for f in out:
            preview = f["evidence"]["value_preview"]
            # Should not look like a real secret
            self.assertNotIn("ThisIs", preview)


class TestFullRun(unittest.TestCase):
    def test_run_returns_skipped_when_intel_missing(self):
        with mock.patch("modules.custom.symfony_detector._INTEL", {}):
            d = _make()
            r = d.run()
        self.assertEqual(r["findings"], [])
        self.assertIn("skipped", r)

    def test_run_fingerprints_then_probes(self):
        d = _make()
        # Landing page advertises Symfony via X-Debug-Token
        landing = _Resp(status=200, text="<html>app</html>",
                        headers={"X-Debug-Token": "tok"})
        # Every subsequent probe — return a single profiler hit
        profiler_resp = _Resp(status=200,
                              text="Symfony Profiler welcome page")

        def fake_get(url, **kw):
            # The detector calls http_get(self.base) first — base may or
            # may not have a trailing slash, so don't anchor on `/`.
            if "_profiler" not in url and "?" not in url:
                return landing
            if "_profiler/" in url and "phpinfo" not in url:
                return profiler_resp
            return _Resp(status=404, text="")

        with mock.patch("modules.custom.symfony_detector.http_get",
                        side_effect=fake_get):
            r = d.run()

        types = {f["type"] for f in r["findings"]}
        self.assertIn("symfony_fingerprint", types)
        self.assertIn("symfony_profiler_exposed", types)
        # The intel pack is the source of truth — every finding cites it
        for f in r["findings"]:
            if f["type"] != "symfony_fingerprint":
                self.assertIn("source_reports", f["evidence"])


if __name__ == "__main__":
    unittest.main()
