"""End-to-end tests for the FastAPI layer.

Uses FastAPI's TestClient — no real HTTP server, just an in-process
ASGI stub. ScannerEngine is patched out so tests don't spawn real
network probes against example.com.
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

# Make sure HunterPy root is importable when running `python -m unittest`
# directly from this directory.
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from fastapi.testclient import TestClient

from gui.backend.app import create_app
from gui.backend.services import scan_manager


class _FakeEngine:
    """Stand-in for ScannerEngine that finishes instantly."""
    def __init__(self, settings):
        self.settings = settings
        # Mimic the real attribute surface used by ScanManager
        from utils.database import Database
        self.db = Database(":memory:")
        self.session = type("S", (), {"scan_id": None})()
        self.all_findings = [
            {"id": "F1", "module": "headers", "type": "missing_security_header",
             "severity": "MEDIUM", "classification": "COMMON",
             "title": "Missing CSP", "url": "https://example.com/"},
            {"id": "F2", "module": "ssl", "type": "weak_cipher",
             "severity": "HIGH", "classification": "INTERESTING",
             "title": "Weak cipher", "url": "https://example.com/"},
        ]
        self._safe_run = lambda name, module: {"findings": []}

    def run(self):
        # Mimic the engine's behaviour: call _safe_run for each module
        # so ScanManager's instrumentation can fire.
        for m in self.settings.modules:
            self._safe_run(m, None)


class APITestCase(unittest.TestCase):
    def setUp(self) -> None:
        scan_manager.reset_for_tests()
        self.app = create_app()
        self.client = TestClient(self.app)

    # ---------- health / root ----------
    def test_root(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("HunterPy API", r.json()["name"])

    def test_healthz(self):
        self.assertEqual(self.client.get("/healthz").json(), {"status": "ok"})

    # ---------- target validation ----------
    def test_validate_target_accepts_clean_domain(self):
        r = self.client.post("/api/scans/validate-target",
                             json={"target": "example.com"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["valid"])

    def test_validate_target_rejects_localhost(self):
        r = self.client.post("/api/scans/validate-target",
                             json={"target": "localhost"})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["valid"])

    def test_validate_target_rejects_gov(self):
        r = self.client.post("/api/scans/validate-target",
                             json={"target": "agency.gov"})
        self.assertFalse(r.json()["valid"])

    # ---------- scan CRUD ----------
    def test_create_scan_rejects_bad_target(self):
        r = self.client.post("/api/scans",
                             json={"target": "localhost", "mode": "passive"})
        self.assertEqual(r.status_code, 400)

    def test_create_and_list_scan(self):
        r = self.client.post("/api/scans",
                             json={"target": "example.com", "mode": "passive"})
        self.assertEqual(r.status_code, 201)
        scan_id = r.json()["id"]
        self.assertTrue(scan_id.startswith("scan_"))

        r2 = self.client.get("/api/scans")
        self.assertEqual(r2.status_code, 200)
        ids = [s["id"] for s in r2.json()["scans"]]
        self.assertIn(scan_id, ids)
        self.assertEqual(r2.json()["total"], 1)

    def test_get_unknown_scan_404(self):
        r = self.client.get("/api/scans/scan_nope")
        self.assertEqual(r.status_code, 404)

    def test_delete_scan(self):
        scan_id = self.client.post(
            "/api/scans", json={"target": "example.com", "mode": "passive"}
        ).json()["id"]
        r = self.client.delete(f"/api/scans/{scan_id}")
        self.assertEqual(r.status_code, 200)
        # Now it should be gone
        self.assertEqual(self.client.get(f"/api/scans/{scan_id}").status_code, 404)

    # ---------- scan lifecycle (patched engine) ----------
    def test_start_runs_via_fake_engine(self):
        scan_id = self.client.post(
            "/api/scans",
            json={"target": "example.com", "mode": "passive",
                  "modules": ["headers", "ssl"]},
        ).json()["id"]

        with patch("gui.backend.services.scan_manager.ScannerEngine", _FakeEngine):
            r = self.client.post(f"/api/scans/{scan_id}/start")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["status"], "running")

        # Wait for thread to finish
        import time as _t
        for _ in range(40):
            r = self.client.get(f"/api/scans/{scan_id}")
            if r.json()["status"] in ("completed", "failed", "cancelled"):
                break
            _t.sleep(0.05)
        body = self.client.get(f"/api/scans/{scan_id}").json()
        self.assertEqual(body["status"], "completed")
        self.assertEqual(body["findings_count"], 2)
        self.assertEqual(body["findings_by_severity"].get("MEDIUM"), 1)
        self.assertEqual(body["findings_by_severity"].get("HIGH"),   1)
        self.assertEqual(body["findings_by_tier"].get("INTERESTING"), 1)

    def test_progress_endpoint_shape(self):
        scan_id = self.client.post(
            "/api/scans", json={"target": "example.com", "mode": "passive"}
        ).json()["id"]
        r = self.client.get(f"/api/scans/{scan_id}/progress")
        self.assertEqual(r.status_code, 200)
        for key in ("scan_id", "phase", "percent", "modules_completed",
                    "modules_total", "status"):
            self.assertIn(key, r.json())

    def test_logs_endpoint(self):
        scan_id = self.client.post(
            "/api/scans", json={"target": "example.com", "mode": "passive"}
        ).json()["id"]
        r = self.client.get(f"/api/scans/{scan_id}/logs")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(any("scan created" in l for l in r.json()["logs"]))

    def test_modules_endpoint(self):
        scan_id = self.client.post(
            "/api/scans",
            json={"target": "example.com", "mode": "custom",
                  "modules": ["headers", "ssl", "fingerprint"]},
        ).json()["id"]
        r = self.client.get(f"/api/scans/{scan_id}/modules")
        self.assertEqual(r.status_code, 200)
        names = [m["name"] for m in r.json()]
        self.assertEqual(names, ["headers", "ssl", "fingerprint"])
        # All should be pending before start
        for m in r.json():
            self.assertEqual(m["status"], "pending")

    def test_cancel_endpoint_marks_state(self):
        scan_id = self.client.post(
            "/api/scans", json={"target": "example.com", "mode": "passive"}
        ).json()["id"]
        # Cancelling a not-running scan returns 200 but doesn't change status
        r = self.client.post(f"/api/scans/{scan_id}/cancel")
        self.assertEqual(r.status_code, 200)

    # ---------- tools / settings / auth ----------
    def test_tools_endpoint(self):
        r = self.client.get("/api/tools")
        self.assertEqual(r.status_code, 200)
        names = {t["name"] for t in r.json()}
        # Required scanners we declared
        self.assertIn("nmap", names)
        self.assertIn("nikto", names)

    def test_settings_round_trip(self):
        before = self.client.get("/api/settings").json()
        self.assertIn("default_mode", before)
        r = self.client.put("/api/settings",
                            json={"default_threads": 42, "garbage_key": 1})
        self.assertEqual(r.status_code, 200)
        after = self.client.get("/api/settings").json()
        self.assertEqual(after["default_threads"], 42)
        self.assertNotIn("garbage_key", after)

    def test_login_stub(self):
        r = self.client.post("/api/auth/login",
                             json={"username": "u", "password": "p"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["token"].startswith("hunterpy-stub-token-"))

    def test_login_rejects_empty(self):
        r = self.client.post("/api/auth/login",
                             json={"username": "", "password": ""})
        self.assertEqual(r.status_code, 400)

    # ---------- reports ----------
    def test_reports_list_empty(self):
        r = self.client.get("/api/reports")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["total"], 0)

    def test_report_templates(self):
        r = self.client.get("/api/reports/templates")
        self.assertEqual(r.status_code, 200)
        formats = {t["format"] for t in r.json()["templates"]}
        self.assertEqual(formats, {"json", "html", "markdown", "burp"})

    # ---------- exploit endpoint is disabled by design ----------
    def test_exploit_endpoint_returns_501(self):
        r = self.client.post("/api/findings/whatever/exploit")
        self.assertEqual(r.status_code, 501)

    # ---------- user-agent presets ----------
    def test_user_agent_catalogue_endpoint(self):
        r = self.client.get("/api/user-agents")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("default", data)
        self.assertIn("strategies", data)
        self.assertIn("presets", data)
        # Default preset is the honest-disclosure UA
        self.assertIn("HunterPy", data["default"])
        # Strategies match what the selector supports
        self.assertEqual(sorted(data["strategies"]),
                         sorted(("static", "rotate-random", "rotate-sequential")))
        # Several presets are present
        names = {p["name"] for p in data["presets"]}
        for must in ("chrome-windows", "firefox-linux", "desktop-browsers",
                     "googlebot"):
            self.assertIn(must, names)
        # Impersonation presets are flagged with the right category
        gb = next(p for p in data["presets"] if p["name"] == "googlebot")
        self.assertEqual(gb["category"], "noisy_impersonation")

    def test_create_scan_with_user_agent_preset_option(self):
        """The scan create endpoint must accept user_agent_preset in options
        and the Settings built by ScanManager must reflect it."""
        captured_settings = []

        class _CapturingEngine(_FakeEngine):
            def __init__(self, settings):
                captured_settings.append(settings)
                super().__init__(settings)

        r = self.client.post("/api/scans", json={
            "target":  "example.com",
            "mode":    "passive",
            "modules": ["headers"],
            "options": {"user_agent_preset": "chrome-windows",
                         "user_agent_strategy": "static"},
        })
        self.assertIn(r.status_code, (200, 201), r.text)
        scan_id = r.json()["id"]

        with patch("gui.backend.services.scan_manager.ScannerEngine",
                    _CapturingEngine):
            r = self.client.post(f"/api/scans/{scan_id}/start")
            self.assertEqual(r.status_code, 200, r.text)
            # Wait for the bg thread to construct the engine
            import time as _t
            for _ in range(80):
                if captured_settings:
                    break
                _t.sleep(0.02)

        self.assertTrue(captured_settings,
                        "ScanManager never built a Settings/engine")
        s = captured_settings[0]
        self.assertIsNotNone(s.ua_selector)
        # The preset's primary UA should be in s.user_agent
        self.assertIn("Chrome", s.user_agent)


if __name__ == "__main__":
    unittest.main()
