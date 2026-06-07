import unittest

from classifiers.dedup_engine import DedupEngine


class TestDedupEngine(unittest.TestCase):
    def test_dedups_identical(self):
        engine = DedupEngine()
        out = engine.deduplicate([
            {"module": "nikto", "type": "x", "url": "https://x.com/", "title": "a"},
            {"module": "nikto", "type": "x", "url": "https://x.com/", "title": "a"},
        ])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["duplicate_count"], 2)

    def test_keeps_different(self):
        engine = DedupEngine()
        out = engine.deduplicate([
            {"module": "nikto", "type": "x", "url": "https://x.com/", "title": "a"},
            {"module": "nikto", "type": "y", "url": "https://x.com/", "title": "a"},
            {"module": "ssl",   "type": "x", "url": "https://x.com/", "title": "a"},
        ])
        self.assertEqual(len(out), 3)

    def test_keeps_highest_severity(self):
        engine = DedupEngine()
        out = engine.deduplicate([
            {"module": "m", "type": "t", "url": "u", "title": "a", "severity": "LOW"},
            {"module": "m", "type": "t", "url": "u", "title": "a", "severity": "HIGH"},
        ])
        self.assertEqual(out[0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
