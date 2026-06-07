"""End-to-end wiring tests for the SECREP* intel pack integration.

Ensures the new finding types are recognized by every downstream system:
classifier, context graph, PoC generator, impact analyzer, CLI choices,
mode presets, and the engine MODULE_MAP.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from classifiers.context_graph import ContextGraph
from classifiers.finding_classifier import (
    FindingClassifier, INTERESTING_TYPES,
)
from reporting.impact_analyzer import ImpactAnalyzer
from reporting.poc_generator import PoCGenerator


SYMFONY_TYPES = [
    "symfony_profiler_exposed",
    "symfony_profiler_phpinfo",
    "symfony_profiler_lfi",
    "symfony_profiler_search",
    "symfony_legacy_dev_front_controller",
    "symfony_legacy_profiler",
    "symfony_legacy_parameters_yml",
    "symfony_fragment_endpoint",
    "symfony_app_env_injection",
    "symfony_app_debug_injection",
    "symfony_exposed_credentials",
    "imagemagick_vulnerable_version",
    "eol_php_with_dangerous_functions",
    "unrestricted_file_upload",
]


class TestClassifierKnowsAllNewTypes(unittest.TestCase):
    def test_every_symfony_type_is_interesting(self):
        for t in SYMFONY_TYPES:
            self.assertIn(t, INTERESTING_TYPES,
                          msg=f"{t} should be in INTERESTING_TYPES")

    def test_classifier_assigns_interesting_tier(self):
        clf = FindingClassifier()
        for t in SYMFONY_TYPES:
            f = clf.classify({
                "module": "symfony", "type": t,
                "title": f"test-{t}", "url": "https://x.com/",
                "severity": "HIGH",
            })
            self.assertEqual(f["classification"], "INTERESTING",
                             msg=f"type={t} classified as {f['classification']}")


class TestPoCGeneratorCoversNewTypes(unittest.TestCase):
    def test_every_symfony_type_has_a_poc_builder(self):
        gen = PoCGenerator()
        for t in SYMFONY_TYPES:
            poc = gen.generate({"type": t, "url": "https://x.com/",
                                 "title": "x", "evidence": {"needle": "APP_SECRET="}})
            # PoC steps should never be empty for a known type
            self.assertTrue(poc.steps, f"no PoC steps for {t}")
            # Remediation should be defined
            self.assertTrue(poc.remediation, f"no remediation for {t}")
            # The SECREP doc should be referenced for Symfony PoCs
            if t.startswith(("symfony_", "imagemagick_", "eol_", "unrestricted_")):
                refs_blob = " ".join(poc.references)
                self.assertIn("docs/threat-intel/SECREP", refs_blob,
                              f"{t} doesn't cite a SECREP report")


class TestImpactAnalyzerCoversNewTypes(unittest.TestCase):
    def test_every_symfony_type_has_data_at_risk_mapping(self):
        a = ImpactAnalyzer()
        for t in SYMFONY_TYPES:
            i = a.analyze({"type": t, "severity": "HIGH",
                            "classification": "INTERESTING"})
            self.assertNotEqual(
                i.data_at_risk, "unknown",
                msg=f"{t} has no _DATA_AT_RISK mapping")
            self.assertIn(i.priority_tier, ("P1", "P2", "P3", "P4"))


class TestContextGraphChains(unittest.TestCase):
    def test_symfony_full_pwnage_chain_fires(self):
        cg = ContextGraph()
        findings = [
            {"type": "symfony_profiler_exposed", "url": "https://t.example/_profiler/"},
            {"type": "symfony_profiler_lfi",
             "url": "https://t.example/_profiler/open?file=config/packages/security.yaml"},
        ]
        chains = cg.detect_chains(findings)
        names = [c["type"] for c in chains]
        self.assertIn("chain_symfony_full_pwnage", names)

    def test_dev_mode_in_prod_chain_fires(self):
        cg = ContextGraph()
        findings = [
            {"type": "symfony_app_env_injection",
             "url": "https://t.example/?+--env=dev"},
            {"type": "symfony_profiler_exposed",
             "url": "https://t.example/_profiler/"},
        ]
        chains = cg.detect_chains(findings)
        self.assertIn("chain_symfony_dev_mode_in_prod",
                      [c["type"] for c in chains])

    def test_imagemagick_upload_chain_fires(self):
        cg = ContextGraph()
        findings = [
            {"type": "unrestricted_file_upload",
             "url": "https://t.example/admin/upload"},
            {"type": "imagemagick_vulnerable_version",
             "url": "https://t.example/"},
        ]
        chains = cg.detect_chains(findings)
        self.assertIn("chain_imagemagick_upload_rce_recipe",
                      [c["type"] for c in chains])

    def test_no_chain_without_full_predicate_match(self):
        cg = ContextGraph()
        chains = cg.detect_chains(
            [{"type": "symfony_profiler_exposed", "url": "x"}])
        # symfony_full_pwnage needs BOTH a profiler exposure AND a leak
        self.assertNotIn("chain_symfony_full_pwnage",
                          [c["type"] for c in chains])


class TestModulePipelineWiring(unittest.TestCase):
    def test_symfony_in_module_map(self):
        from core.scanner_engine import ScannerEngine
        self.assertIn("symfony", ScannerEngine.MODULE_MAP)

    def test_symfony_in_phase1_recon(self):
        from core.scanner_engine import ScannerEngine
        self.assertIn("symfony", ScannerEngine.EXECUTION_PIPELINE["phase1_recon"])

    def test_symfony_in_every_default_mode(self):
        from argparse import Namespace
        from config.settings import Settings
        ns = Namespace(target="example.com", target_list=None, scope=None,
                       mode="passive", modules=None, threads=2, timeout=5,
                       rate_limit=5, delay=0.1, auth_url=None,
                       username=None, username_list=None, password_list=None,
                       proxy=None, user_agent=None, cookies=None,
                       output="/tmp/x", format="json", verbose=False,
                       no_color=False, headers=None, no_nvd=True,
                       nvd_offline=True, nvd_api_key=None,
                       dorks_active=False, confirm_dork_scraping=False,
                       dork_max_queries=5, dork_max_results=10,
                       dork_templates=None, dork_extra="")
        for mode in ("passive", "quick", "standard", "full", "stealth"):
            ns.mode = mode
            s = Settings(ns)
            self.assertIn("symfony", s.modules,
                          msg=f"symfony missing from {mode} preset")

    def test_symfony_in_cli_choices(self):
        # Run the help text and grep for the choice
        out = subprocess.run([sys.executable, "main.py", "--help"],
                             capture_output=True, text=True, timeout=15)
        # `symfony` should appear in the --modules choice list
        self.assertIn("symfony", out.stdout)


class TestVulnerabilityDBExtension(unittest.TestCase):
    def test_db_includes_imagemagick_and_symfony_entries(self):
        path = os.path.join(os.path.dirname(__file__), "..", "signatures",
                            "vulnerability_db.json")
        with open(path, "r", encoding="utf-8") as f:
            db = json.load(f)
        products = {entry["product"] for entry in db["cves"]}
        self.assertIn("imagemagick", products)
        self.assertIn("symfony", products)


class TestDorkTemplateAdded(unittest.TestCase):
    def test_symfony_dork_template_present(self):
        from modules.osint.dork_builder import DorkBuilder
        b = DorkBuilder()
        names = {t["name"] for t in b.list_templates()}
        self.assertIn("symfony_exposure", names)

    def test_symfony_dorks_substitute_target(self):
        from modules.osint.dork_builder import DorkBuilder
        b = DorkBuilder()
        out = b.build("example.com", only=["symfony_exposure"])
        self.assertTrue(out.dorks)
        for d in out.dorks:
            self.assertIn("example.com", d.query)


if __name__ == "__main__":
    unittest.main()
