"""Tests for the module-coverage helper.

The coverage helper is what makes "I thought I ran nuclei" impossible —
it always tells the operator exactly which modules ran at full vs
fallback vs skipped tiers.
"""
from __future__ import annotations

import unittest

from core.module_coverage import (
    CoverageReport, MODULE_DEPS, StrictModeError,
    build_coverage_report, enforce_strict_mode, render_banner,
)


def _status(available_tools):
    """Mock a ToolPathValidator.check_all_tools() return value."""
    return {
        name: {"available": True, "path": f"/usr/bin/{name}",
               "version": "1.0", "required": True}
        for name in available_tools
    }


class CatalogueShapeTests(unittest.TestCase):
    def test_every_external_module_has_entry(self):
        for must in ("nikto", "nuclei", "sqlmap", "gobuster", "ffuf",
                     "wfuzz", "hydra"):
            self.assertIn(must, MODULE_DEPS)
            dep = MODULE_DEPS[must]
            self.assertIsNotNone(dep.requires_tool,
                                  f"{must} must declare its external tool")

    def test_native_modules_have_no_required_tool(self):
        for must in ("headers", "ssl", "fingerprint", "endpoints",
                     "surface", "symfony", "cors"):
            self.assertIn(must, MODULE_DEPS)
            self.assertTrue(MODULE_DEPS[must].is_native,
                             f"{must} should be native (no external tool)")

    def test_fallback_modules_have_a_note(self):
        for must in ("gobuster", "ffuf"):
            dep = MODULE_DEPS[must]
            self.assertTrue(dep.has_fallback)
            self.assertTrue(dep.fallback_note,
                             f"{must} declares a fallback but no note")


class BuildCoverageTests(unittest.TestCase):
    def test_native_modules_are_native_tier(self):
        r = build_coverage_report(["headers", "ssl"], tool_status={})
        tiers = [e.tier for e in r.entries]
        self.assertEqual(tiers, ["native", "native"])

    def test_external_module_with_tool_is_full(self):
        r = build_coverage_report(["nikto"], tool_status=_status(["nikto"]))
        self.assertEqual(r.entries[0].tier, "full")
        self.assertEqual(r.entries[0].tool, "nikto")
        self.assertTrue(r.entries[0].tool_present)

    def test_external_module_without_tool_and_no_fallback_is_skipped(self):
        r = build_coverage_report(["nuclei"], tool_status=_status([]))
        self.assertEqual(r.entries[0].tier, "skipped")
        self.assertFalse(r.entries[0].tool_present)
        self.assertIn("--install-tools", r.entries[0].note)

    def test_external_module_without_tool_but_with_fallback_is_fallback(self):
        r = build_coverage_report(["gobuster"], tool_status=_status([]))
        self.assertEqual(r.entries[0].tier, "fallback")
        self.assertFalse(r.entries[0].tool_present)
        self.assertIn("Python", r.entries[0].note)

    def test_unknown_module_defaults_to_native_not_crash(self):
        r = build_coverage_report(["definitely_not_a_real_module"],
                                   tool_status={})
        self.assertEqual(r.entries[0].tier, "native")

    def test_mixed_scan_buckets_correctly(self):
        r = build_coverage_report(
            ["headers", "nikto", "nuclei", "gobuster"],
            tool_status=_status(["nikto"]))
        buckets = r.by_tier()
        self.assertEqual(len(buckets["native"]), 1)   # headers
        self.assertEqual(len(buckets["full"]), 1)     # nikto
        self.assertEqual(len(buckets["skipped"]), 1)  # nuclei
        self.assertEqual(len(buckets["fallback"]), 1) # gobuster

    def test_to_dict_includes_summary_and_degraded_count(self):
        r = build_coverage_report(["nuclei", "gobuster"], tool_status=_status([]))
        d = r.to_dict()
        self.assertIn("entries", d)
        self.assertIn("summary", d)
        self.assertEqual(d["degraded_count"], 2)


class StrictModeTests(unittest.TestCase):
    def test_strict_passes_when_everything_full(self):
        r = build_coverage_report(["headers", "nikto"],
                                   tool_status=_status(["nikto"]))
        # Should not raise
        enforce_strict_mode(r)

    def test_strict_fails_on_skipped(self):
        r = build_coverage_report(["nuclei"], tool_status=_status([]))
        with self.assertRaises(StrictModeError) as ctx:
            enforce_strict_mode(r)
        self.assertIn("nuclei", str(ctx.exception))
        self.assertIn("--install-tools", str(ctx.exception))

    def test_strict_also_fails_on_fallback(self):
        # Fallback is still degraded — strict means strict.
        r = build_coverage_report(["gobuster"], tool_status=_status([]))
        with self.assertRaises(StrictModeError):
            enforce_strict_mode(r)


class ModuleDependencyTests(unittest.TestCase):
    def test_sqlmap_declares_endpoints_dependency(self):
        self.assertIn("endpoints", MODULE_DEPS["sqlmap"].requires_modules)

    def test_unmet_returns_missing_when_module_not_in_plan(self):
        from core.module_coverage import unmet_module_requirements
        unmet = unmet_module_requirements(
            "sqlmap", available_modules=["sqlmap"], completed_modules=[])
        self.assertEqual(unmet, ["endpoints"])

    def test_unmet_returns_empty_when_dep_completed(self):
        from core.module_coverage import unmet_module_requirements
        unmet = unmet_module_requirements(
            "sqlmap", available_modules=["sqlmap", "endpoints"],
            completed_modules=["endpoints"])
        self.assertEqual(unmet, [])

    def test_unmet_treats_skipped_completion_as_unmet(self):
        from core.module_coverage import unmet_module_requirements
        # endpoints was in the plan but did NOT complete (skipped).
        unmet = unmet_module_requirements(
            "sqlmap", available_modules=["sqlmap", "endpoints"],
            completed_modules=[])
        self.assertEqual(unmet, ["endpoints"])

    def test_module_without_deps_never_unmet(self):
        from core.module_coverage import unmet_module_requirements
        self.assertEqual(
            unmet_module_requirements("headers", available_modules=[]),
            [])


class BannerRenderTests(unittest.TestCase):
    def test_banner_includes_per_module_row(self):
        r = build_coverage_report(["headers", "nikto"], tool_status=_status([]))
        lines = render_banner(r)
        # First line is the summary
        self.assertIn("Module coverage:", lines[0])
        # One row per module
        joined = "\n".join(lines)
        self.assertIn("headers", joined)
        self.assertIn("nikto", joined)

    def test_banner_glyphs_distinguish_tiers(self):
        r = build_coverage_report(
            ["headers", "nikto", "nuclei", "gobuster"],
            tool_status=_status(["nikto"]))
        lines = render_banner(r)
        joined = "\n".join(lines)
        self.assertIn("✓", joined)  # nikto (full)
        self.assertIn("✗", joined)  # nuclei (skipped)
        self.assertIn("⚠", joined)  # gobuster (fallback)
        self.assertIn("·", joined)  # headers (native)


if __name__ == "__main__":
    unittest.main()
