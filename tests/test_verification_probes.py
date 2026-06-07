"""Tests for individual verification probes (Symfony + generic).

We never make real network calls. Each test patches the probe's
``_http_get`` injection point with a fake that returns a canned
``HTTPResponse``.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Dict, List

from modules.exploit.probes.base import PROBE_REGISTRY, get_probe
from modules.exploit.results import SafetyLevel, VerificationStatus
from utils.http_client import HTTPResponse


def _settings(target="example.com"):
    return SimpleNamespace(target=target, timeout=5,
                            user_agent="test", cookies=None)


def _resp(status=200, body="", headers=None, url="https://example.com/"):
    return HTTPResponse(
        status_code=status, url=url,
        headers=headers or {"Content-Type": "text/html"},
        text=body,
    )


class _Recorder:
    """Records the URLs requested and returns canned responses."""

    def __init__(self, responses):
        # responses: list of (substring_to_match, HTTPResponse) tuples,
        # OR a single HTTPResponse to return for everything.
        self.responses = responses
        self.calls: List[str] = []

    def __call__(self, url, headers=None, timeout=None, **kw):
        self.calls.append(url)
        if isinstance(self.responses, HTTPResponse):
            return self.responses
        for substr, resp in self.responses:
            if substr in url:
                return resp
        return None


# ---------------------------------------------------------------------------
class RegistryTests(unittest.TestCase):
    def test_symfony_probes_registered(self):
        for ft in ("symfony_profiler_phpinfo", "symfony_profiler_lfi",
                   "symfony_profiler_exposed", "symfony_app_env_injection",
                   "symfony_exposed_credentials", "symfony_legacy_profiler"):
            self.assertIn(ft, PROBE_REGISTRY, f"missing probe for {ft}")

    def test_generic_probes_registered(self):
        for ft in ("git_exposed", "env_exposed", "admin_panel",
                   "source_map_exposed", "unrestricted_file_upload"):
            self.assertIn(ft, PROBE_REGISTRY, f"missing probe for {ft}")


# ---------------------------------------------------------------------------
class SymfonyProfilerPhpinfoTests(unittest.TestCase):
    def test_confirmed_when_phpinfo_with_secret(self):
        body = """<html>PHP Version 5.6.40
        <tr><td>APP_SECRET</td><td>supersecretvalueAAA</td></tr>
        <tr><td>DATABASE_URL</td><td>mysql://root:pw@db/x</td></tr></html>"""
        cls = get_probe("symfony_profiler_phpinfo")
        probe = cls(finding={"type": "symfony_profiler_phpinfo",
                              "url": "https://example.com/_profiler/phpinfo"},
                    settings=_settings(),
                    http_get_func=_Recorder(_resp(200, body)))
        result = probe.execute()
        self.assertEqual(result.status, VerificationStatus.CONFIRMED)
        self.assertEqual(result.safety_level, SafetyLevel.READ_ONLY)
        self.assertIn("APP_SECRET", result.proof)
        # Values must be hashed, not stored
        self.assertNotIn("supersecretvalueAAA", str(result.to_dict()))
        # PHP version captured
        self.assertEqual(result.proof_artifacts["php_version"], "5.6.40")
        # consent header was sent
        self.assertTrue(any("X-HunterPy-Verify" in ex.request_headers
                             for ex in result.exchanges))

    def test_inconclusive_on_404(self):
        cls = get_probe("symfony_profiler_phpinfo")
        probe = cls(finding={"type": "symfony_profiler_phpinfo",
                              "url": "https://example.com/_profiler/phpinfo"},
                    settings=_settings(),
                    http_get_func=_Recorder(_resp(404, "Not Found")))
        result = probe.execute()
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)

    def test_safe_failed_on_no_response(self):
        cls = get_probe("symfony_profiler_phpinfo")
        probe = cls(finding={"type": "symfony_profiler_phpinfo",
                              "url": "https://example.com/_profiler/phpinfo"},
                    settings=_settings(),
                    http_get_func=lambda *a, **k: None)
        result = probe.execute()
        self.assertEqual(result.status, VerificationStatus.SAFE_FAILED)


class SymfonyProfilerLFITests(unittest.TestCase):
    def test_confirmed_on_hostname_read(self):
        cls = get_probe("symfony_profiler_lfi")
        probe = cls(finding={"type": "symfony_profiler_lfi",
                              "url": "https://example.com/foo"},
                    settings=_settings(),
                    http_get_func=_Recorder(_resp(200, "web-server-01\n")))
        result = probe.execute()
        self.assertEqual(result.status, VerificationStatus.CONFIRMED)
        self.assertEqual(result.proof_artifacts["hostname_length"], 13)

    def test_inconclusive_on_html_error_page(self):
        cls = get_probe("symfony_profiler_lfi")
        probe = cls(finding={"type": "symfony_profiler_lfi",
                              "url": "https://example.com/foo"},
                    settings=_settings(),
                    http_get_func=_Recorder(
                        _resp(200, "<!doctype html><h1>Error</h1>"
                                    "<p>nope</p>" * 5)))
        result = probe.execute()
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)

    def test_falls_back_to_legacy_path(self):
        rec = _Recorder([
            ("app_dev.php/_profiler/open", _resp(200, "legacy-host\n")),
        ])
        cls = get_probe("symfony_profiler_lfi")
        probe = cls(finding={"type": "symfony_profiler_lfi",
                              "url": "https://example.com/x"},
                    settings=_settings(), http_get_func=rec)
        result = probe.execute()
        self.assertEqual(result.status, VerificationStatus.CONFIRMED)


class SymfonyAppEnvInjectionTests(unittest.TestCase):
    def test_confirmed_when_trick_toggles_toolbar(self):
        rec = _Recorder([
            ("?+--env=dev", _resp(200, "<html>sfWebDebugToolbar</html>")),
            ("",            _resp(200, "<html>normal page</html>")),
        ])
        cls = get_probe("symfony_app_env_injection")
        probe = cls(finding={"type": "symfony_app_env_injection",
                              "url": "https://example.com/"},
                    settings=_settings(), http_get_func=rec)
        result = probe.execute()
        self.assertEqual(result.status, VerificationStatus.CONFIRMED)

    def test_inconclusive_when_both_have_toolbar(self):
        rec = _Recorder(_resp(200, "<html>sfWebDebugToolbar</html>"))
        cls = get_probe("symfony_app_env_injection")
        probe = cls(finding={"type": "symfony_app_env_injection",
                              "url": "https://example.com/"},
                    settings=_settings(), http_get_func=rec)
        result = probe.execute()
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)


class SymfonyProfilerExposedTests(unittest.TestCase):
    def test_confirmed_when_toolbar_present(self):
        cls = get_probe("symfony_profiler_exposed")
        probe = cls(finding={"type": "symfony_profiler_exposed",
                              "url": "https://example.com/_profiler/"},
                    settings=_settings(),
                    http_get_func=_Recorder(_resp(200,
                        "<html>Symfony Profiler token=abc1234 "
                        "sfWebDebugToolbar token=def5678</html>")))
        result = probe.execute()
        self.assertEqual(result.status, VerificationStatus.CONFIRMED)
        self.assertGreaterEqual(result.proof_artifacts["request_tokens_visible"], 1)


# ---------------------------------------------------------------------------
class GenericProbeTests(unittest.TestCase):
    def test_git_exposed_confirmed_on_valid_ref(self):
        cls = get_probe("git_exposed")
        probe = cls(finding={"type": "git_exposed",
                              "url": "https://example.com/.git/HEAD"},
                    settings=_settings(),
                    http_get_func=_Recorder(_resp(200, "ref: refs/heads/main\n")))
        result = probe.execute()
        self.assertEqual(result.status, VerificationStatus.CONFIRMED)

    def test_git_exposed_inconclusive_on_404(self):
        cls = get_probe("git_exposed")
        probe = cls(finding={"type": "git_exposed",
                              "url": "https://example.com/.git/"},
                    settings=_settings(),
                    http_get_func=_Recorder(_resp(404, "Not Found")))
        result = probe.execute()
        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)

    def test_env_exposed_confirmed(self):
        cls = get_probe("env_exposed")
        probe = cls(finding={"type": "env_exposed",
                              "url": "https://example.com/.env"},
                    settings=_settings(),
                    http_get_func=_Recorder(_resp(200,
                        "APP_KEY=base64:abc\nDB_HOST=localhost\nDB_USER=root")))
        result = probe.execute()
        self.assertEqual(result.status, VerificationStatus.CONFIRMED)
        self.assertGreaterEqual(result.proof_artifacts["dotenv_line_count"], 2)

    def test_admin_panel_confirmed_on_login_ui(self):
        body = "<html><form><input name=password><button>Sign in</button></form></html>"
        cls = get_probe("admin_panel")
        probe = cls(finding={"type": "admin_panel",
                              "url": "https://example.com/admin/"},
                    settings=_settings(),
                    http_get_func=_Recorder(_resp(200, body)))
        result = probe.execute()
        self.assertEqual(result.status, VerificationStatus.CONFIRMED)

    def test_admin_panel_does_NOT_attempt_login(self):
        # The probe must only do a single GET, no POST attempts.
        rec = _Recorder(_resp(200, "<form><input name=password></form>"))
        cls = get_probe("admin_panel")
        probe = cls(finding={"type": "admin_panel",
                              "url": "https://example.com/admin/"},
                    settings=_settings(), http_get_func=rec)
        probe.execute()
        self.assertEqual(len(rec.calls), 1)
        # Only GET exchanges should be recorded
        for ex in probe.exchanges:
            self.assertEqual(ex.method, "GET")


# ---------------------------------------------------------------------------
class UploadProbeShapeTests(unittest.TestCase):
    """We only verify the probe declares the right contract — the actual
    multipart POST path requires the `requests` lib and a target."""

    def test_safety_level_is_trivial_write(self):
        cls = get_probe("unrestricted_file_upload")
        probe = cls(finding={"type": "unrestricted_file_upload",
                              "upload_url": "https://example.com/upload",
                              "upload_field": "file"},
                    settings=_settings())
        self.assertEqual(probe.safety_level, SafetyLevel.TRIVIAL_WRITE)

    def test_skipped_when_no_upload_url(self):
        cls = get_probe("unrestricted_file_upload")
        probe = cls(finding={"type": "unrestricted_file_upload"},
                    settings=_settings())
        result = probe.execute()
        # Either SKIPPED (no requests lib at all) or SKIPPED (no URL).
        self.assertEqual(result.status, VerificationStatus.SKIPPED)

    def test_marker_never_uses_executable_extension(self):
        """Static check: read the source and assert no .php/.phtml/etc."""
        import inspect
        from modules.exploit.probes import upload
        src = inspect.getsource(upload)
        for forbidden in (".php\"", ".phtml\"", ".phar\"", ".asp\"",
                          ".jsp\"", ".exe\""):
            self.assertNotIn(forbidden, src,
                             f"upload probe must NEVER write {forbidden}")


if __name__ == "__main__":
    unittest.main()
