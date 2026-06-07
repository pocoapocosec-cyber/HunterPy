"""Tests for the default-credentials check module.

We never make a real HTTP POST. Each test patches `requests.post` to
return canned responses and asserts the module's behaviour: capped
attempts, single-shot per pair, no creds in evidence (only hash), and
the right hit/miss heuristic.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from modules.auth_testing.default_cred_check import (
    DEFAULT_PAIRS, DefaultCredCheckModule,
)


def _settings(**kw):
    base = dict(
        target="https://example.com", auth_url=None,
        timeout=5, user_agent="test", mode="standard",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _resp(status=200, content_len=200, location=None):
    m = MagicMock()
    m.status_code = status
    m.content = b"x" * content_len
    m.headers = {"Location": location} if location else {}
    return m


class PairCatalogueTests(unittest.TestCase):
    def test_catalogue_is_bounded(self):
        # Anything beyond ~20 pairs is brute-force, not "default-cred audit".
        self.assertLessEqual(len(DEFAULT_PAIRS), 25)
        self.assertGreaterEqual(len(DEFAULT_PAIRS), 15)

    def test_admin_admin_present(self):
        self.assertIn(("admin", "admin"), DEFAULT_PAIRS)


class EndpointResolutionTests(unittest.TestCase):
    def test_explicit_auth_url_wins(self):
        m = DefaultCredCheckModule(
            _settings(auth_url="https://example.com/admin/login"))
        self.assertEqual(m._resolve_endpoints(),
                          ["https://example.com/admin/login"])

    def test_recon_admin_findings_are_used(self):
        m = DefaultCredCheckModule(_settings())
        m.set_context({"findings": [
            {"type": "admin_panel", "url": "https://example.com/admin/"},
            {"type": "login_form",  "url": "https://example.com/login"},
            {"type": "missing_csp", "url": "https://example.com/"},
        ]})
        self.assertEqual(set(m._resolve_endpoints()),
                          {"https://example.com/admin/",
                           "https://example.com/login"})

    def test_falls_back_to_guesses(self):
        m = DefaultCredCheckModule(_settings())
        out = m._resolve_endpoints()
        self.assertTrue(any("login" in u for u in out))


class HitDetectionTests(unittest.TestCase):
    def test_redirect_to_different_location_is_a_hit(self):
        baseline = {"status": 200, "length": 1500, "location": None}
        attempt  = {"status": 302, "length": 0,    "location": "/dashboard"}
        self.assertTrue(
            DefaultCredCheckModule._is_login_success(baseline, attempt))

    def test_same_status_huge_body_diff_is_a_hit(self):
        baseline = {"status": 200, "length": 1500, "location": None}
        attempt  = {"status": 200, "length": 200,  "location": None}
        self.assertTrue(
            DefaultCredCheckModule._is_login_success(baseline, attempt))

    def test_identical_response_is_NOT_a_hit(self):
        baseline = {"status": 200, "length": 1500, "location": None}
        attempt  = {"status": 200, "length": 1505, "location": None}
        self.assertFalse(
            DefaultCredCheckModule._is_login_success(baseline, attempt))

    def test_baseline_401_attempt_200_with_length_change_is_hit(self):
        baseline = {"status": 401, "length": 200, "location": None}
        attempt  = {"status": 200, "length": 1500, "location": None}
        self.assertTrue(
            DefaultCredCheckModule._is_login_success(baseline, attempt))


class RunIntegrationTests(unittest.TestCase):
    def _make(self, **kw):
        m = DefaultCredCheckModule(_settings(**kw))
        m.attempt_delay = 0    # speed up tests; production keeps 0.5s
        return m

    def test_no_endpoint_means_skipped(self):
        m = self._make()
        # Patch _resolve_endpoints to return nothing
        with patch.object(m, "_resolve_endpoints", return_value=[]):
            out = m.run()
        self.assertEqual(out["findings"], [])
        self.assertIn("skipped", out)

    def test_no_hit_reports_no_findings(self):
        m = self._make(auth_url="https://x.example/login")
        with patch("requests.post", return_value=_resp(401, 200)):
            out = m.run()
        self.assertEqual(out["findings"], [])

    def test_first_hit_short_circuits_remaining_attempts(self):
        m = self._make(auth_url="https://x.example/login")
        responses = [
            _resp(401, 200),                              # baseline
            _resp(302, 0, location="/dashboard"),         # first pair hits
        ]
        with patch("requests.post", side_effect=responses) as mock_post:
            out = m.run()
        self.assertEqual(len(out["findings"]), 1)
        self.assertEqual(out["findings"][0]["type"], "weak_credentials")
        self.assertEqual(mock_post.call_count, 2)

    def test_evidence_never_contains_plaintext_credentials(self):
        m = self._make(auth_url="https://x.example/login")
        responses = [
            _resp(401, 200),
            _resp(302, 0, location="/dashboard"),
        ]
        with patch("requests.post", side_effect=responses):
            out = m.run()
        ev = out["findings"][0]["evidence"]
        ev_text = str(ev) + str(out["findings"][0])
        self.assertIn("pair_sha256", ev)
        self.assertNotIn("admin:admin", ev_text)
        self.assertNotIn("admin\":\"admin", ev_text)

    def test_attempts_capped_at_three_endpoints(self):
        m = self._make()
        m.endpoints = [f"https://x.example/login{i}" for i in range(10)]
        with patch("requests.post", return_value=_resp(401, 200)) as mock_post:
            m.run()
        # Cap: 3 endpoints * 21 attempts (1 baseline + up to 20 pairs)
        self.assertLessEqual(mock_post.call_count, 3 * (1 + len(DEFAULT_PAIRS)))

    def test_baseline_failure_reports_unreachable_finding(self):
        m = self._make(auth_url="https://x.example/login")
        with patch("requests.post", side_effect=Exception("connection refused")):
            out = m.run()
        self.assertEqual(out["findings"][0]["type"], "endpoint_unreachable")
        self.assertTrue(out["findings"][0]["likely_false_alarm"])


class HeadersTests(unittest.TestCase):
    def test_every_request_carries_hunterpy_verify_header(self):
        m = DefaultCredCheckModule(
            _settings(auth_url="https://x.example/login"))
        m.attempt_delay = 0
        with patch("requests.post", return_value=_resp(401, 200)) as mock_post:
            m.run()
        # Every call must have set the X-HunterPy-Verify header so blue
        # teams can correlate this traffic.
        for call in mock_post.call_args_list:
            headers = call.kwargs.get("headers", {})
            self.assertIn("X-HunterPy-Verify", headers)


if __name__ == "__main__":
    unittest.main()
