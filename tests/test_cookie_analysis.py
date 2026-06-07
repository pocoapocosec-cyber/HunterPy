"""Tests for HeaderAnalyzer._analyze_cookies."""
from __future__ import annotations

import unittest

from modules.custom.header_analyzer import HeaderAnalyzer


class TestCookieAnalysis(unittest.TestCase):
    def test_full_flags(self):
        cookies = HeaderAnalyzer._analyze_cookies([
            "session=abc; Path=/; HttpOnly; Secure; SameSite=Strict",
        ])
        self.assertEqual(len(cookies), 1)
        c = cookies[0]
        self.assertEqual(c["name"], "session")
        self.assertTrue(c["httponly"])
        self.assertTrue(c["secure"])
        self.assertEqual(c["samesite"], "Strict")

    def test_missing_flags(self):
        cookies = HeaderAnalyzer._analyze_cookies(["foo=bar"])
        self.assertEqual(len(cookies), 1)
        c = cookies[0]
        self.assertFalse(c["httponly"])
        self.assertFalse(c["secure"])
        self.assertIsNone(c["samesite"])

    def test_partial_flags(self):
        cookies = HeaderAnalyzer._analyze_cookies([
            "x=1; HttpOnly",
            "y=2; Secure; SameSite=Lax",
        ])
        self.assertEqual(len(cookies), 2)
        self.assertTrue(cookies[0]["httponly"])
        self.assertFalse(cookies[0]["secure"])
        self.assertEqual(cookies[1]["samesite"], "Lax")

    def test_skips_malformed(self):
        cookies = HeaderAnalyzer._analyze_cookies(["", "no-equals", "good=1; Secure"])
        # malformed ones silently dropped
        self.assertEqual(len(cookies), 1)
        self.assertEqual(cookies[0]["name"], "good")


if __name__ == "__main__":
    unittest.main()
