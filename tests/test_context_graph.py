"""Tests for the cross-finding attack-chain detector."""
import unittest

from classifiers.context_graph import ContextGraph


class TestContextGraph(unittest.TestCase):
    def test_dev_subdomain_plus_git_chain(self):
        cg = ContextGraph()
        findings = [
            {"type": "dev_subdomain", "url": "https://dev.example.com/"},
            {"type": "git_exposed",   "url": "https://dev.example.com/.git/HEAD"},
        ]
        chains = cg.detect_chains(findings)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["type"], "chain_exposed_source_on_dev_subdomain")
        self.assertTrue(chains[0]["interesting"])

    def test_cors_plus_cookie_chain(self):
        cg = ContextGraph()
        findings = [
            {"type": "cors_with_credentials", "url": "https://x.com/"},
            {"type": "weak_cookie",           "url": "https://x.com/",
             "evidence": {"name": "session", "missing_flags": ["HttpOnly"]}},
        ]
        chains = cg.detect_chains(findings)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["type"],
                         "chain_cors_wildcard_with_session_cookie")

    def test_no_chain_when_predicate_missing(self):
        cg = ContextGraph()
        findings = [{"type": "git_exposed", "url": "https://x.com/.git/HEAD"}]
        self.assertEqual(cg.detect_chains(findings), [])

    def test_sql_plus_admin_chain(self):
        cg = ContextGraph()
        findings = [
            {"type": "sql_injection", "url": "https://x.com/login"},
            {"type": "admin_panel",   "url": "https://x.com/admin/"},
        ]
        chains = cg.detect_chains(findings)
        self.assertEqual(len(chains), 1)
        self.assertIn("sql_injection_plus_admin", chains[0]["type"])

    def test_asset_summary(self):
        cg = ContextGraph()
        cg.add_findings([
            {"url": "https://a.com/x"}, {"url": "https://a.com/y"},
            {"url": "https://b.com/z"},
        ])
        summary = cg.asset_summary()
        self.assertEqual(summary["a.com"], 2)
        self.assertEqual(summary["b.com"], 1)


if __name__ == "__main__":
    unittest.main()
