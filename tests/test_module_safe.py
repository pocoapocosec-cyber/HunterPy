"""Tests for the @module_safe error-handling decorator."""
from __future__ import annotations

import logging
import unittest
from unittest.mock import patch

from utils.module_safe import module_safe


class _Boom(Exception):
    pass


class _FakeModule:
    MODULE_NAME = "fakemod"

    @module_safe(fallback="skip", log_level="warning")
    def crash(self):
        raise _Boom("synthetic failure")

    @module_safe(fallback="skip", log_level="warning")
    def ok(self):
        return {"module": "fakemod", "findings": [{"x": 1}]}

    @module_safe(fallback="empty", log_level="warning")
    def crash_empty(self):
        raise _Boom("bang")

    @module_safe(fallback="raise", log_level="error")
    def crash_raise(self):
        raise _Boom("fatal")


class FallbackTests(unittest.TestCase):
    def test_skip_returns_skipped_dict(self):
        out = _FakeModule().crash()
        self.assertEqual(out["module"], "fakemod")
        self.assertEqual(out["findings"], [])
        self.assertIn("skipped", out)
        self.assertIn("_Boom", out["skipped"])
        self.assertIn("error", out)

    def test_empty_returns_no_skipped_marker(self):
        out = _FakeModule().crash_empty()
        self.assertEqual(out["findings"], [])
        self.assertNotIn("skipped", out)
        self.assertIn("error", out)

    def test_raise_propagates(self):
        with self.assertRaises(_Boom):
            _FakeModule().crash_raise()

    def test_happy_path_passthrough(self):
        out = _FakeModule().ok()
        self.assertEqual(out["findings"], [{"x": 1}])
        self.assertNotIn("error", out)


class IntrospectionTests(unittest.TestCase):
    def test_decorator_attaches_metadata(self):
        # `tests/test_module_safe.py::_FakeModule.crash` was decorated
        # with fallback="skip", log_level="warning".
        meta = _FakeModule.crash.__module_safe__
        self.assertEqual(meta["fallback"], "skip")
        self.assertEqual(meta["log_level"], "warning")

    def test_invalid_fallback_rejected(self):
        with self.assertRaises(ValueError):
            module_safe(fallback="explode")

    def test_invalid_log_level_rejected(self):
        with self.assertRaises(ValueError):
            module_safe(log_level="critical")


class LoggingTests(unittest.TestCase):
    def test_warning_log_level_used(self):
        with self.assertLogs("hunterpy.module_safe", level="WARNING") as cap:
            _FakeModule().crash()
        joined = "\n".join(cap.output)
        self.assertIn("fakemod", joined)
        self.assertIn("_Boom", joined)
        self.assertIn("synthetic failure", joined)


class AppliedToRealModulesTests(unittest.TestCase):
    """Sanity checks that the decorator is actually applied where it
    matters."""

    def test_symfony_detector_is_decorated(self):
        from modules.custom.symfony_detector import SymfonyDetector
        self.assertTrue(hasattr(SymfonyDetector.run, "__module_safe__"))

    def test_default_creds_is_decorated(self):
        from modules.auth_testing.default_cred_check import (
            DefaultCredCheckModule,
        )
        self.assertTrue(hasattr(DefaultCredCheckModule.run, "__module_safe__"))


if __name__ == "__main__":
    unittest.main()
