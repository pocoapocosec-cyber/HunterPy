"""Tests for the OOB collaborator (local listener + token generator)."""
from __future__ import annotations

import time
import unittest
import urllib.error
import urllib.request

from modules.exploit.collaborator import (
    CallbackHit, LocalCollaborator, make_collaborator, new_token,
)


class TokenTests(unittest.TestCase):
    def test_tokens_are_unique(self):
        tokens = {new_token() for _ in range(100)}
        self.assertEqual(len(tokens), 100)

    def test_tokens_carry_prefix(self):
        t = new_token("xyz")
        self.assertTrue(t.startswith("xyz-"))


class LocalCollaboratorTests(unittest.TestCase):
    def test_lifecycle_start_stop(self):
        c = LocalCollaborator(host="127.0.0.1", port=0)
        url = c.start()
        try:
            self.assertTrue(url.startswith("http://"))
            self.assertIn(":", url)
        finally:
            c.stop()

    def test_records_hit_with_token(self):
        with LocalCollaborator(host="127.0.0.1", port=0) as c:
            tok = new_token()
            target = c.url_for(tok, path="/cb")
            req = urllib.request.Request(target,
                                         headers={"User-Agent": "tcb"})
            urllib.request.urlopen(req, timeout=3).read()
            hit = c.wait_for_hit(tok, timeout=2)
            self.assertIsNotNone(hit, "hit should have been recorded")
            self.assertEqual(hit.token, tok)
            self.assertEqual(hit.method, "GET")
            self.assertIn("tcb", hit.headers.get("User-Agent", ""))

    def test_wait_for_hit_times_out_cleanly(self):
        with LocalCollaborator(host="127.0.0.1", port=0) as c:
            self.assertIsNone(c.wait_for_hit("never-fired", timeout=0.3))


class FactoryTests(unittest.TestCase):
    def test_explicit_empty_disables_collaborator(self):
        self.assertIsNone(make_collaborator(""))

    def test_default_returns_local(self):
        c = make_collaborator(None)
        self.assertIsInstance(c, LocalCollaborator)


if __name__ == "__main__":
    unittest.main()
