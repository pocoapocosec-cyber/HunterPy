"""Tests for the signed authorization file."""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

from modules.exploit.authorization import (
    Authorization, AuthorizationError, create_authorization,
    ensure_authorized, load_authorization, write_authorization,
)


KEY = b"x" * 32


class AuthorizationFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "engagement.auth.json")

    def tearDown(self):
        self.tmp.cleanup()

    def _make(self, **overrides):
        defaults = dict(
            engagement="test", operator="op", hostnames=["example.com"],
            valid_days=1, max_safety_level="trivial_write", key=KEY,
        )
        defaults.update(overrides)
        return create_authorization(**defaults)

    def test_create_and_roundtrip(self):
        auth = self._make()
        write_authorization(auth, self.path)
        self.assertTrue(os.path.exists(self.path))
        # File should be 0600
        mode = os.stat(self.path).st_mode & 0o777
        self.assertEqual(mode, 0o600)
        loaded = load_authorization(self.path, key=KEY)
        self.assertEqual(loaded.engagement, "test")
        self.assertEqual(loaded.hostnames, ["example.com"])

    def test_tampered_payload_fails_signature(self):
        auth = self._make()
        write_authorization(auth, self.path)
        # Edit the payload directly
        with open(self.path, "r") as f:
            data = json.load(f)
        data["hostnames"].append("attacker.example")
        with open(self.path, "w") as f:
            json.dump(data, f)
        with self.assertRaises(AuthorizationError) as ctx:
            load_authorization(self.path, key=KEY)
        self.assertIn("signature INVALID", str(ctx.exception))

    def test_wrong_key_fails_signature(self):
        auth = self._make()
        write_authorization(auth, self.path)
        with self.assertRaises(AuthorizationError):
            load_authorization(self.path, key=b"y" * 32)

    def test_hostname_scope_glob(self):
        auth = self._make(hostnames=["*.example.com", "literal.com"])
        ensure_authorized(auth, hostname="a.example.com", requested_safety="read_only")
        ensure_authorized(auth, hostname="literal.com", requested_safety="read_only")
        with self.assertRaises(AuthorizationError) as ctx:
            ensure_authorized(auth, hostname="evil.com",
                              requested_safety="read_only")
        self.assertIn("not in the authorization scope", str(ctx.exception))

    def test_expired_authorization_refused(self):
        auth = self._make(valid_days=1)
        # Force expiry by editing in memory then re-signing
        past = (datetime.now(tz=timezone.utc) - timedelta(days=2)).replace(microsecond=0).isoformat()
        auth.expires_at = past
        auth.sign(KEY)
        with self.assertRaises(AuthorizationError) as ctx:
            ensure_authorized(auth, hostname="example.com",
                              requested_safety="read_only")
        self.assertIn("expired", str(ctx.exception))

    def test_safety_level_cap(self):
        auth = self._make(max_safety_level="read_only")
        ensure_authorized(auth, hostname="example.com",
                          requested_safety="read_only")
        with self.assertRaises(AuthorizationError):
            ensure_authorized(auth, hostname="example.com",
                              requested_safety="trivial_write")

    def test_destructive_requires_explicit_opt_in(self):
        auth = self._make(max_safety_level="destructive", allow_destructive=False)
        # caller asks for destructive but auth file doesn't allow it
        with self.assertRaises(AuthorizationError):
            ensure_authorized(auth, hostname="example.com",
                              requested_safety="destructive")

    def test_missing_file_raises(self):
        with self.assertRaises(AuthorizationError):
            load_authorization("/nonexistent/path.json", key=KEY)


if __name__ == "__main__":
    unittest.main()
