"""Tests for the shared HTTP helper."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from utils import http_client
from utils.http_client import HTTPResponse, http_get


class TestHttpGet(unittest.TestCase):
    def test_returns_none_on_failure(self):
        # Direct stdlib path with bogus URL → should return None, not raise
        with patch.object(http_client, "_HAVE_REQUESTS", False):
            r = http_get("http://does-not-exist-x.invalid", timeout=1)
        self.assertIsNone(r)

    def test_response_wrapper_contains_expected_fields(self):
        wrapper = HTTPResponse(
            status_code=200, url="http://x", headers={"X": "y"},
            text="body", cookies={"a": "b"},
            raw_set_cookie=["a=b; HttpOnly"],
        )
        self.assertEqual(wrapper.status_code, 200)
        self.assertEqual(wrapper.headers["X"], "y")
        self.assertEqual(wrapper.cookies["a"], "b")
        self.assertEqual(wrapper.raw_set_cookie[0], "a=b; HttpOnly")


if __name__ == "__main__":
    unittest.main()
