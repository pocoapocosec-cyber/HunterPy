"""Tests for the YAML frontmatter block at the top of the markdown report."""
from __future__ import annotations

import re
import unittest

from core.markdown_report import render_markdown


class FrontmatterTests(unittest.TestCase):
    def _render(self, findings=None):
        return render_markdown(
            target="example.com",
            metadata={"scan_id": "abc-123", "mode": "passive",
                       "end_time": "2026-06-07T12:00:00Z",
                       "modules_run": ["headers", "ssl"]},
            findings=findings or [],
        )

    def test_starts_with_yaml_frontmatter(self):
        out = self._render()
        self.assertTrue(out.startswith("---\n"),
                        "report must begin with '---\\n' (YAML opener)")
        # Closing fence within first 4KB
        self.assertIn("\n---\n", out[:4000])

    def test_includes_scan_metadata(self):
        out = self._render()
        self.assertIn("scan_id: 'abc-123'", out)
        self.assertIn("target: 'example.com'", out)
        self.assertIn("mode: 'passive'", out)
        self.assertIn("tool: 'HunterPy'", out)

    def test_findings_summary_counts_by_severity(self):
        findings = [
            {"type": "sql_injection", "severity": "CRITICAL",
             "title": "SQLi"},
            {"type": "sql_injection", "severity": "HIGH", "title": "SQLi"},
            {"type": "missing_security_header", "severity": "MEDIUM",
             "title": "Missing CSP"},
        ]
        out = self._render(findings)
        self.assertIn("total: 3", out)
        self.assertIn("critical: 1", out)
        self.assertIn("high: 1", out)
        self.assertIn("medium: 1", out)

    def test_attack_chains_block_appears_when_present(self):
        findings = [
            {"type": "chain_symfony_full_pwnage", "severity": "CRITICAL",
             "title": "Full pwnage chain",
             "steps": ["profiler_exposed", "leaked_db_creds", "admin_panel"]},
        ]
        out = self._render(findings)
        self.assertIn("attack_chains:", out)
        self.assertIn("type: 'chain_symfony_full_pwnage'", out)
        self.assertIn("steps:", out)
        self.assertIn("- 'profiler_exposed'", out)

    def test_verification_summary_appears_when_present(self):
        findings = [
            {"type": "symfony_profiler_phpinfo", "severity": "CRITICAL",
             "title": "phpinfo",
             "verification": {"status": "confirmed", "probe_name": "x"}},
            {"type": "git_exposed", "severity": "HIGH", "title": "git",
             "verification": {"status": "inconclusive", "probe_name": "y"}},
        ]
        out = self._render(findings)
        self.assertIn("verification_summary:", out)
        self.assertIn("confirmed: 1", out)
        self.assertIn("inconclusive: 1", out)

    def test_single_quote_in_target_is_escaped(self):
        out = render_markdown(target="ex'ample.com", metadata={}, findings=[])
        # Embedded ' must be doubled, never break the YAML
        self.assertIn("target: 'ex''ample.com'", out)


if __name__ == "__main__":
    unittest.main()
