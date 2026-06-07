"""Tests for the user-agent selection feature."""
from __future__ import annotations

import os
import random
import tempfile
import threading
import unittest
from types import SimpleNamespace

from config.user_agents import (
    DEFAULT_USER_AGENT, PRESETS, UAPreset, UserAgentSelector,
    list_presets, load_pool_file, resolve_preset,
)


class PresetCatalogueTests(unittest.TestCase):
    def test_default_preset_is_honest_disclosure(self):
        self.assertIn("default", PRESETS)
        self.assertEqual(PRESETS["default"].user_agents, [DEFAULT_USER_AGENT])

    def test_common_browser_presets_present(self):
        for name in ("chrome-windows", "firefox-linux", "safari-ios",
                     "chrome-android", "edge-windows", "desktop-browsers",
                     "all-browsers"):
            self.assertIn(name, PRESETS, f"missing preset {name}")

    def test_impersonation_presets_marked_noisy(self):
        for name in ("googlebot", "bingbot"):
            self.assertIn(name, PRESETS)
            self.assertEqual(PRESETS[name].category, "noisy_impersonation")
            # Description must call out the legal/operational risk
            self.assertIn("IMPERSONATION",
                          PRESETS[name].description.upper())

    def test_multi_ua_presets_have_more_than_one(self):
        for name in ("desktop-browsers", "mobile-browsers", "all-browsers"):
            self.assertGreater(len(PRESETS[name].user_agents), 1)

    def test_list_presets_returns_serialisable_data(self):
        out = list_presets()
        self.assertIsInstance(out, list)
        for entry in out:
            self.assertIn("name", entry)
            self.assertIn("category", entry)
            self.assertIn("description", entry)
            self.assertIn("count", entry)

    def test_resolve_preset_raises_on_unknown(self):
        with self.assertRaises(ValueError) as ctx:
            resolve_preset("definitely-not-a-preset")
        self.assertIn("unknown user-agent preset", str(ctx.exception))


class LoadPoolFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "uas.txt")

    def tearDown(self):
        self.tmp.cleanup()

    def test_loads_one_per_line_ignoring_comments(self):
        with open(self.path, "w") as f:
            f.write("# this is a comment\n")
            f.write("Mozilla/5.0 (A)\n")
            f.write("\n")
            f.write("  Mozilla/5.0 (B)  \n")
            f.write("# trailing comment\n")
        out = load_pool_file(self.path)
        self.assertEqual(out, ["Mozilla/5.0 (A)", "Mozilla/5.0 (B)"])

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_pool_file("/no/such/file.txt")

    def test_empty_file_raises(self):
        with open(self.path, "w") as f:
            f.write("# only comments\n\n")
        with self.assertRaises(ValueError):
            load_pool_file(self.path)


class UserAgentSelectorTests(unittest.TestCase):
    def test_static_returns_first_entry(self):
        sel = UserAgentSelector(["A", "B", "C"], strategy="static")
        for _ in range(5):
            self.assertEqual(sel.next(), "A")

    def test_sequential_rotates(self):
        sel = UserAgentSelector(["A", "B", "C"], strategy="rotate-sequential")
        out = [sel.next() for _ in range(7)]
        self.assertEqual(out, ["A", "B", "C", "A", "B", "C", "A"])

    def test_random_picks_from_pool(self):
        rng = random.Random(42)
        sel = UserAgentSelector(["A", "B", "C"], strategy="rotate-random",
                                 rng=rng)
        picks = {sel.next() for _ in range(50)}
        self.assertTrue(picks.issubset({"A", "B", "C"}))
        # Likelihood of all-same in 50 picks across 3 options is ~1e-23
        self.assertGreater(len(picks), 1)

    def test_empty_pool_rejected(self):
        with self.assertRaises(ValueError):
            UserAgentSelector([], strategy="static")

    def test_unknown_strategy_rejected(self):
        with self.assertRaises(ValueError):
            UserAgentSelector(["A"], strategy="rotate-every-other-tuesday")

    def test_current_is_always_first(self):
        sel = UserAgentSelector(["A", "B"], strategy="rotate-sequential")
        sel.next()        # advance the cycle
        sel.next()
        self.assertEqual(sel.current(), "A")

    def test_describe_is_a_string(self):
        sel = UserAgentSelector(["A"], strategy="static")
        self.assertIsInstance(sel.describe(), str)
        self.assertIn("static", sel.describe())

    def test_sequential_rotation_is_thread_safe(self):
        # Round-robin under concurrent next() calls must visit each
        # entry a deterministic number of times in total.
        sel = UserAgentSelector(["A", "B", "C"], strategy="rotate-sequential")
        results = []
        lock = threading.Lock()

        def worker():
            for _ in range(100):
                v = sel.next()
                with lock:
                    results.append(v)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(results), 800)
        # Each UA should appear close to 800/3 times — exact balance
        # depends on interleaving but the worst case is still bounded.
        for ua in ("A", "B", "C"):
            self.assertGreater(results.count(ua), 200)


class FromArgsTests(unittest.TestCase):
    def test_explicit_pool_wins(self):
        sel = UserAgentSelector.from_args(
            single="single-ua", preset="chrome-linux",
            pool=["P1", "P2"], pool_file=None, strategy="static")
        self.assertEqual(sel.pool, ["P1", "P2"])

    def test_pool_file_used_when_no_pool(self):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        tmp.write("F1\nF2\n")
        tmp.close()
        try:
            sel = UserAgentSelector.from_args(
                single="single-ua", preset="chrome-linux",
                pool=None, pool_file=tmp.name, strategy="static")
            self.assertEqual(sel.pool, ["F1", "F2"])
        finally:
            os.unlink(tmp.name)

    def test_preset_used_when_no_pool_or_file(self):
        sel = UserAgentSelector.from_args(
            single="single-ua", preset="chrome-linux",
            pool=None, pool_file=None, strategy="static")
        self.assertEqual(sel.pool, PRESETS["chrome-linux"].user_agents)

    def test_single_used_when_nothing_else(self):
        sel = UserAgentSelector.from_args(
            single="my-custom-ua", preset=None, pool=None,
            pool_file=None, strategy="static")
        self.assertEqual(sel.pool, ["my-custom-ua"])

    def test_default_when_everything_missing(self):
        sel = UserAgentSelector.from_args(
            single=None, preset=None, pool=None,
            pool_file=None, strategy="static")
        self.assertEqual(sel.pool, [DEFAULT_USER_AGENT])

    def test_rotation_collapses_to_static_when_pool_size_one(self):
        # Asking for rotation with a 1-item pool is meaningless — must
        # not crash, must downgrade to static and log a warning.
        sel = UserAgentSelector.from_args(
            single="only-one", preset=None, pool=None,
            pool_file=None, strategy="rotate-random")
        self.assertEqual(sel.strategy, "static")


class SettingsIntegrationTests(unittest.TestCase):
    """The Settings object must build a working ua_selector."""

    def _ns(self, **overrides):
        base = dict(
            target="example.com", target_list=None, scope=None,
            mode="passive", modules=None, threads=10, timeout=30,
            rate_limit=10, delay=0.1, auth_url=None, username=None,
            username_list=None, password_list=None, proxy=None,
            user_agent=None, user_agent_preset=None,
            user_agent_pool=None, user_agent_file=None,
            user_agent_strategy="static", cookies=None,
            output="./output", format="all", verbose=False,
            no_color=True, headers=None,
            no_nvd=True, nvd_offline=False, nvd_api_key=None,
            dorks_active=False, confirm_dork_scraping=False,
            dork_max_queries=5, dork_max_results=10,
            dork_templates=None, dork_extra="",
            verify=False, verify_auth_file=None,
            verify_non_interactive=False, verify_allow_destructive=False,
            verify_rate_limit_per_sec=0.5, verify_only_types=None,
            verify_max_findings=50, verify_collaborator_url=None,
        )
        base.update(overrides)
        return SimpleNamespace(**base)

    def test_default_selector_uses_default_ua(self):
        from config.settings import Settings
        s = Settings(self._ns())
        self.assertIsNotNone(s.ua_selector)
        self.assertEqual(s.ua_selector.current(), DEFAULT_USER_AGENT)
        self.assertEqual(s.user_agent, DEFAULT_USER_AGENT)

    def test_preset_applied(self):
        from config.settings import Settings
        s = Settings(self._ns(user_agent_preset="chrome-windows"))
        self.assertEqual(s.ua_selector.pool,
                         PRESETS["chrome-windows"].user_agents)
        # user_agent (legacy field) should be in sync with selector.current()
        self.assertEqual(s.user_agent, s.ua_selector.current())

    def test_pool_applied_with_rotation(self):
        from config.settings import Settings
        s = Settings(self._ns(
            user_agent_pool=["A", "B", "C"],
            user_agent_strategy="rotate-sequential"))
        self.assertEqual(s.ua_selector.pool, ["A", "B", "C"])
        self.assertEqual(s.ua_selector.strategy, "rotate-sequential")

    def test_pool_file_applied(self):
        from config.settings import Settings
        tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        tmp.write("FromFile1\nFromFile2\n")
        tmp.close()
        try:
            s = Settings(self._ns(user_agent_file=tmp.name,
                                   user_agent_strategy="rotate-random"))
            self.assertEqual(s.ua_selector.pool,
                             ["FromFile1", "FromFile2"])
        finally:
            os.unlink(tmp.name)

    def test_bad_preset_falls_back_to_default_without_crashing(self):
        from config.settings import Settings
        s = Settings(self._ns(user_agent_preset="not-a-real-preset"))
        # selector must exist and use the default, not crash the scan
        self.assertIsNotNone(s.ua_selector)
        self.assertEqual(s.ua_selector.current(), DEFAULT_USER_AGENT)

    def test_missing_pool_file_falls_back_to_default(self):
        from config.settings import Settings
        s = Settings(self._ns(user_agent_file="/no/such/file.txt"))
        self.assertIsNotNone(s.ua_selector)
        self.assertEqual(s.ua_selector.current(), DEFAULT_USER_AGENT)

    def test_single_user_agent_string_still_works(self):
        """Backwards-compat: --user-agent without preset/pool keeps working."""
        from config.settings import Settings
        s = Settings(self._ns(user_agent="MyToolUA/1.0"))
        self.assertEqual(s.user_agent, "MyToolUA/1.0")
        self.assertEqual(s.ua_selector.current(), "MyToolUA/1.0")


class HttpClientHelperTests(unittest.TestCase):
    """``http_get_with_settings`` should pick the rotated UA per call."""

    def test_uses_rotated_ua_on_each_call(self):
        from utils import http_client as hc

        captured = []
        def fake_http_get(url, **kw):
            captured.append(kw.get("user_agent"))
            return None

        sel = UserAgentSelector(["A", "B", "C"], strategy="rotate-sequential")
        settings = SimpleNamespace(ua_selector=sel, user_agent="A")

        orig = hc.http_get
        hc.http_get = fake_http_get
        try:
            hc.http_get_with_settings(settings, "https://x.example/1")
            hc.http_get_with_settings(settings, "https://x.example/2")
            hc.http_get_with_settings(settings, "https://x.example/3")
        finally:
            hc.http_get = orig
        self.assertEqual(captured, ["A", "B", "C"])

    def test_uses_static_ua_when_strategy_static(self):
        from utils import http_client as hc

        captured = []
        def fake_http_get(url, **kw):
            captured.append(kw.get("user_agent"))
            return None

        sel = UserAgentSelector(["A", "B"], strategy="static")
        settings = SimpleNamespace(ua_selector=sel, user_agent="A")

        orig = hc.http_get
        hc.http_get = fake_http_get
        try:
            hc.http_get_with_settings(settings, "https://x.example/1")
            hc.http_get_with_settings(settings, "https://x.example/2")
        finally:
            hc.http_get = orig
        self.assertEqual(captured, ["A", "A"])

    def test_falls_back_to_settings_user_agent_when_no_selector(self):
        from utils import http_client as hc

        captured = []
        def fake_http_get(url, **kw):
            captured.append(kw.get("user_agent"))
            return None

        settings = SimpleNamespace(ua_selector=None, user_agent="LegacyUA")
        orig = hc.http_get
        hc.http_get = fake_http_get
        try:
            hc.http_get_with_settings(settings, "https://x.example/1")
        finally:
            hc.http_get = orig
        self.assertEqual(captured, ["LegacyUA"])


class VerifierConsentHeaderTests(unittest.TestCase):
    """Verification probes must preserve the X-HunterPy-Verify marker even
    when the operator configured a fake-browser UA pool."""

    def test_consent_marker_always_in_user_agent(self):
        from modules.exploit.probes.base import Probe
        from modules.exploit.results import SafetyLevel

        class _Dummy(Probe):
            probe_name = "test"
            safety_level = SafetyLevel.READ_ONLY
            def execute(self):
                return self._new_result(
                    __import__("modules.exploit.results",
                                fromlist=["VerificationStatus"]).VerificationStatus.SKIPPED,
                    "ok")

        sel = UserAgentSelector(PRESETS["chrome-windows"].user_agents,
                                 strategy="static")
        settings = SimpleNamespace(ua_selector=sel, user_agent="",
                                    timeout=5)
        probe = _Dummy(finding={"type": "x", "url": "https://example.com"},
                        settings=settings)
        hdrs = probe._consent_headers()
        # Marker present
        self.assertIn("X-HunterPy-Verify", hdrs)
        # Base UA is from the preset
        self.assertIn("Chrome", hdrs["User-Agent"])
        # And the verify-marker is always appended
        self.assertIn("verify/", hdrs["User-Agent"])
        self.assertIn(probe.consent_marker, hdrs["User-Agent"])


if __name__ == "__main__":
    unittest.main()
