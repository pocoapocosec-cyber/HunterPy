"""Tests for the behavioral baseline analyzer (no network)."""
import tempfile
import unittest
from argparse import Namespace
from unittest.mock import patch

from config.settings import Settings
from modules.intelligence.baseline_analyzer import BehaviorAnalyzer


def _settings():
    ns = Namespace(target="example.com", target_list=None, scope=None,
                   mode="passive", modules=None, threads=2, timeout=5,
                   rate_limit=5, delay=0.1, auth_url=None,
                   username=None, username_list=None, password_list=None,
                   proxy=None, user_agent=None, cookies=None,
                   output=tempfile.mkdtemp(), format="json", verbose=False,
                   no_color=False, headers=None,
                   no_nvd=True, nvd_offline=True, nvd_api_key=None)
    return Settings(ns)


def _fake_response(status, length):
    """Build a stub HTTPResponse-ish object the analyzer's _probe can read."""
    class _Resp:
        def __init__(self):
            self.status_code = status
            self.text = "x" * length
            self.headers = {"Server": "nginx"}
    return _Resp()


class TestBaselineEstablishment(unittest.TestCase):
    def test_baseline_records_404_signatures(self):
        ba = BehaviorAnalyzer(_settings())
        responses = [_fake_response(200, 2000)]      # /
        responses += [_fake_response(404, 350)] * 7  # 7 random 404 probes
        it = iter(responses)
        with patch("modules.intelligence.baseline_analyzer.http_get",
                   side_effect=lambda *a, **k: next(it, None)):
            b = ba.establish()
        self.assertGreater(b.samples, 0)
        self.assertIn(350, b.common_404_bodies)

    def test_score_detects_soft_404(self):
        ba = BehaviorAnalyzer(_settings())
        # build baseline with 404=300 bytes
        responses = [_fake_response(200, 1500)]
        responses += [_fake_response(404, 300)] * 7
        it = iter(responses)
        with patch("modules.intelligence.baseline_analyzer.http_get",
                   side_effect=lambda *a, **k: next(it, None)):
            ba.establish()
        score = ba.score_response(status=200, length=300)
        self.assertTrue(score["soft_404"])
        self.assertGreaterEqual(score["anomaly"], 0.5)

    def test_score_flags_large_length_deviation(self):
        ba = BehaviorAnalyzer(_settings())
        # baseline lengths around 1000 with low stdev
        responses = [_fake_response(200, l) for l in
                     (1000, 1020, 980, 1010, 990, 1005, 995, 1000)]
        it = iter(responses)
        with patch("modules.intelligence.baseline_analyzer.http_get",
                   side_effect=lambda *a, **k: next(it, None)):
            ba.establish()
        score = ba.score_response(status=200, length=50000)
        self.assertGreater(score["anomaly"], 0.4)
        self.assertTrue(any("length" in r for r in score["reasons"]))

    def test_score_without_baseline_safe(self):
        ba = BehaviorAnalyzer(_settings())
        score = ba.score_response(status=200, length=100)
        self.assertEqual(score["anomaly"], 0.0)


if __name__ == "__main__":
    unittest.main()
