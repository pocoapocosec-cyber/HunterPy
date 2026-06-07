"""Tests for the per-mode (level, risk) SQLMap defaults + CLI overrides."""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from modules.injection.sqlmap_module import SQLMapModule


def _settings(mode="standard", **kw):
    base = dict(
        target="https://example.com", mode=mode, threads=4, timeout=15,
        rate_limit=10, output_dir="/tmp",
        proxy=None, cookies=None, user_agent="test",
        sqlmap_level=None, sqlmap_risk=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


class ModeDefaultsTests(unittest.TestCase):
    def _level_risk_for(self, mode, **kw):
        m = SQLMapModule(_settings(mode=mode, **kw))
        return m._resolve_level_risk()

    def test_passive_quick_stay_at_level_1(self):
        self.assertEqual(self._level_risk_for("passive"), (1, 1))
        self.assertEqual(self._level_risk_for("quick"), (1, 1))

    def test_standard_bumps_level_to_2(self):
        self.assertEqual(self._level_risk_for("standard"), (2, 1))

    def test_full_uses_level_3_risk_2(self):
        self.assertEqual(self._level_risk_for("full"), (3, 2))

    def test_strict_matches_full(self):
        self.assertEqual(self._level_risk_for("strict"), (3, 2))

    def test_stealth_stays_safe(self):
        self.assertEqual(self._level_risk_for("stealth"), (1, 1))


class CLIOverrideTests(unittest.TestCase):
    def test_explicit_level_overrides_mode_default(self):
        m = SQLMapModule(_settings(mode="quick", sqlmap_level=4))
        lvl, risk = m._resolve_level_risk()
        self.assertEqual(lvl, 4)
        # risk should still use the quick default (1)
        self.assertEqual(risk, 1)

    def test_explicit_risk_overrides_mode_default(self):
        m = SQLMapModule(_settings(mode="standard", sqlmap_risk=3))
        lvl, risk = m._resolve_level_risk()
        self.assertEqual(lvl, 2)
        self.assertEqual(risk, 3)

    def test_clamps_to_valid_ranges(self):
        # level 99 → 5; risk 0 → 1
        m = SQLMapModule(_settings(sqlmap_level=99, sqlmap_risk=0))
        lvl, risk = m._resolve_level_risk()
        self.assertEqual(lvl, 5)
        self.assertEqual(risk, 1)


class CmdEmissionTests(unittest.TestCase):
    def test_cmd_includes_resolved_level_and_risk(self):
        m = SQLMapModule(_settings(mode="full"))
        cmd = m._cmd("https://example.com/?id=1")
        # Find --level <N>
        idx = cmd.index("--level")
        self.assertEqual(cmd[idx + 1], "3")
        idx = cmd.index("--risk")
        self.assertEqual(cmd[idx + 1], "2")

    def test_cmd_respects_cli_override(self):
        m = SQLMapModule(_settings(mode="passive", sqlmap_level=5,
                                    sqlmap_risk=3))
        cmd = m._cmd("https://example.com/?id=1")
        self.assertEqual(cmd[cmd.index("--level") + 1], "5")
        self.assertEqual(cmd[cmd.index("--risk") + 1], "3")


if __name__ == "__main__":
    unittest.main()
