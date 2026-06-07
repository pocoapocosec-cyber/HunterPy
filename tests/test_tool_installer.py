"""Tests for the tool installer.

We never actually execute apt/brew/pip in tests — every call to
``subprocess.run`` is patched. The point is to verify:

  * platform detection picks the right package manager
  * plan building emits the right argv per platform
  * dry-run never runs anything
  * sudo steps refuse to execute when sudo isn't valid
  * the lockfile round-trips cleanly
  * Go-module-only tools are NEVER executed even when confirmed
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from config import tool_installer
from config.tool_installer import (
    InstallPlan, InstallStep, PlanResult, StepResult,
    build_plan, execute_plan, read_lockfile, run_installer,
    select_tools, write_lockfile, PINNED_VERSIONS,
)


# ---------------------------------------------------------------------------
def _plat(system="linux", pkg_mgr="apt", **kw):
    base = {"system": system, "distro": "ubuntu", "pkg_mgr": pkg_mgr,
            "python": "/usr/bin/python3", "has_sudo": True, "has_go": False}
    base.update(kw)
    return base


class PinnedVersionsTests(unittest.TestCase):
    def test_every_python_tool_has_a_specific_version(self):
        # sqlmap + wfuzz are pip-installed so they MUST be pinned to a
        # concrete version, not a range — otherwise dry-run lies.
        for tool in ("sqlmap", "wfuzz"):
            self.assertIn(tool, PINNED_VERSIONS)
            v = PINNED_VERSIONS[tool]
            self.assertRegex(v, r"^\d+\.\d+",
                              f"{tool} pin {v!r} must look like a version")

    def test_every_go_tool_is_pinned_to_a_version_tag(self):
        for tool in ("gobuster", "ffuf", "nuclei"):
            self.assertIn(tool, PINNED_VERSIONS)
            self.assertTrue(PINNED_VERSIONS[tool].startswith("v"),
                            f"{tool} pin should be a v-prefixed git tag")


class PlanBuilderTests(unittest.TestCase):
    def test_pip_plan_pins_version(self):
        p = build_plan("sqlmap", _plat())
        self.assertEqual(p.method, "pip")
        self.assertEqual(len(p.steps), 1)
        argv = p.steps[0].argv
        self.assertIn("pip", argv)
        self.assertTrue(any(f"sqlmap==" in a for a in argv),
                        f"sqlmap pip spec missing in {argv}")
        self.assertTrue(any(PINNED_VERSIONS["sqlmap"] in a for a in argv))

    def test_pip_plan_uses_user_install_no_sudo(self):
        p = build_plan("sqlmap", _plat())
        self.assertFalse(p.steps[0].needs_sudo)
        self.assertIn("--user", p.steps[0].argv)

    def test_apt_plan_uses_sudo(self):
        p = build_plan("nikto", _plat(pkg_mgr="apt"))
        self.assertEqual(p.method, "apt")
        self.assertTrue(p.steps[0].needs_sudo)
        self.assertEqual(p.steps[0].argv[:3], ["sudo", "apt-get", "install"])

    def test_brew_plan_no_sudo(self):
        p = build_plan("nikto", _plat(system="darwin", pkg_mgr="brew"))
        self.assertEqual(p.method, "brew")
        self.assertFalse(p.steps[0].needs_sudo)
        self.assertEqual(p.steps[0].argv[:2], ["brew", "install"])

    def test_pacman_plan_uses_noconfirm(self):
        p = build_plan("hydra", _plat(pkg_mgr="pacman"))
        self.assertEqual(p.method, "pacman")
        self.assertIn("--noconfirm", p.steps[0].argv)

    def test_apk_plan(self):
        p = build_plan("hydra", _plat(pkg_mgr="apk"))
        self.assertEqual(p.method, "apk")

    def test_unsupported_platform_returns_manual_plan(self):
        p = build_plan("nikto", _plat(system="windows", pkg_mgr=None))
        self.assertEqual(p.method, "manual")
        self.assertTrue(p.manual_only)

    def test_unknown_tool_returns_manual(self):
        p = build_plan("definitely-not-a-tool", _plat())
        self.assertEqual(p.method, "manual")
        self.assertTrue(p.manual_only)

    def test_go_tools_are_manual_only(self):
        # nuclei has no Debian package → falls through to go-manual.
        p = build_plan("nuclei", _plat(pkg_mgr="apt"))
        self.assertTrue(p.manual_only,
                        "Go-only tools must be manual-only, never auto-run")
        self.assertEqual(p.method, "manual")
        # The printed argv MUST be `go install ...@<pinned>`, never @latest
        argv_str = " ".join(p.steps[0].argv)
        self.assertIn("go", argv_str)
        self.assertNotIn("@latest", argv_str)
        self.assertIn(PINNED_VERSIONS["nuclei"], argv_str)


class ExecutePlanTests(unittest.TestCase):
    def test_already_installed_is_short_circuit(self):
        plan = build_plan("sqlmap", _plat())
        with patch("shutil.which", return_value="/usr/local/bin/sqlmap"), \
             patch("config.tool_paths.ToolPathValidator._version",
                    return_value="1.8.10"):
            r = execute_plan(plan, dry_run=False, has_sudo=True)
        self.assertTrue(r.already_installed)
        self.assertTrue(r.success)
        self.assertTrue(r.skipped)
        self.assertEqual(r.resolved_path, "/usr/local/bin/sqlmap")

    def test_dry_run_never_invokes_subprocess(self):
        plan = build_plan("nikto", _plat())
        with patch("shutil.which", return_value=None), \
             patch("subprocess.run") as mock_run:
            r = execute_plan(plan, dry_run=True, has_sudo=True)
        mock_run.assert_not_called()
        self.assertTrue(r.skipped)
        self.assertFalse(r.success)
        # The plan steps should be recorded as skipped with reason
        for s in r.steps:
            self.assertEqual(s.skipped_reason, "dry-run")
            self.assertFalse(s.ran)

    def test_manual_only_plan_never_executes_even_when_confirmed(self):
        # Critical guarantee: --install-tools-confirm must NOT run Go
        # install steps. We use nuclei which is manual-only.
        plan = build_plan("nuclei", _plat(pkg_mgr="apt"))
        self.assertTrue(plan.manual_only)
        with patch("shutil.which", return_value=None), \
             patch("subprocess.run") as mock_run:
            r = execute_plan(plan, dry_run=False, has_sudo=True)
        mock_run.assert_not_called()
        self.assertTrue(r.skipped)

    def test_sudo_step_refused_when_sudo_missing(self):
        plan = build_plan("nikto", _plat(pkg_mgr="apt"))
        with patch("shutil.which", return_value=None), \
             patch("subprocess.run") as mock_run:
            r = execute_plan(plan, dry_run=False, has_sudo=False)
        mock_run.assert_not_called()
        self.assertFalse(r.success)
        # Each step should be marked skipped with a sudo reason
        for s in r.steps:
            self.assertIn("sudo", s.skipped_reason)

    def test_successful_install_returns_resolved_path(self):
        plan = build_plan("sqlmap", _plat())
        # which() returns None at the start (not installed), then the
        # installed path after the install step ran. Use a counter so
        # the side_effect tolerates extra which() calls.
        call_count = {"n": 0}
        def which_side(cmd):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return None
            return "/home/user/.local/bin/sqlmap"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="ok\n", stderr="")
        with patch("shutil.which", side_effect=which_side), \
             patch("subprocess.run", return_value=completed), \
             patch("config.tool_paths.ToolPathValidator._version",
                    return_value="1.8.10"), \
             patch("config.tool_installer._probe_user_site_paths",
                    return_value=None):
            r = execute_plan(plan, dry_run=False, has_sudo=True)
        self.assertTrue(r.success)
        self.assertFalse(r.skipped)
        self.assertEqual(r.resolved_path, "/home/user/.local/bin/sqlmap")
        self.assertEqual(r.resolved_version, "1.8.10")

    def test_failed_install_records_exit_code(self):
        plan = build_plan("sqlmap", _plat())
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="ERROR: nope\n")
        with patch("shutil.which", return_value=None), \
             patch("subprocess.run", return_value=completed), \
             patch("config.tool_paths.ToolPathValidator._version",
                    return_value="unknown"), \
             patch("config.tool_installer._probe_user_site_paths",
                    return_value=None):
            r = execute_plan(plan, dry_run=False, has_sudo=True)
        self.assertFalse(r.success)
        self.assertEqual(r.steps[0].exit_code, 1)
        self.assertIn("nope", r.steps[0].stderr_tail)


class UserSiteProbeTests(unittest.TestCase):
    """Probing common --user / Go-modules locations when PATH lookup fails."""

    def test_finds_pip_user_install_off_path(self):
        # which() returns None — simulating ~/.local/bin not on PATH — but
        # the probe finds the binary at the user-site location.
        plan = build_plan("sqlmap", _plat())
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="ok\n", stderr="")
        fake_path = "/home/op/.local/bin/sqlmap"
        with patch("shutil.which", return_value=None), \
             patch("subprocess.run", return_value=completed), \
             patch("config.tool_installer._probe_user_site_paths",
                    return_value=fake_path), \
             patch("config.tool_paths.ToolPathValidator._version",
                    return_value="1.8.10"):
            r = execute_plan(plan, dry_run=False, has_sudo=True)
        self.assertTrue(r.success)
        self.assertEqual(r.resolved_path, fake_path)
        self.assertIn("PATH", r.notes,
                      "successful-but-off-PATH install must warn about PATH")


class LockfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "tools.lock.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_round_trip(self):
        results = [
            PlanResult(tool="sqlmap", method="pip",
                       pinned="1.8.10", already_installed=False,
                       skipped=False, success=True,
                       resolved_version="1.8.10",
                       resolved_path="/usr/local/bin/sqlmap"),
            PlanResult(tool="nikto", method="apt",
                       pinned=">=2.5.0", already_installed=True,
                       skipped=True, success=True,
                       resolved_version="2.5.0",
                       resolved_path="/usr/bin/nikto"),
        ]
        write_lockfile(self.path, _plat(), results)
        loaded = read_lockfile(self.path)
        self.assertEqual(loaded["lockfile_version"], 1)
        names = [t["name"] for t in loaded["tools"]]
        self.assertEqual(names, ["sqlmap", "nikto"])
        # sqlmap pin and path round-trip
        sqlmap = next(t for t in loaded["tools"] if t["name"] == "sqlmap")
        self.assertEqual(sqlmap["pinned"], "1.8.10")
        self.assertEqual(sqlmap["resolved_path"], "/usr/local/bin/sqlmap")

    def test_read_missing_file_returns_none(self):
        self.assertIsNone(read_lockfile("/no/such/file.json"))


class SelectToolsTests(unittest.TestCase):
    def test_explicit_only_wins(self):
        self.assertEqual(select_tools(only=["nikto", "sqlmap"]),
                         ["nikto", "sqlmap"])

    def test_required_by_default(self):
        out = select_tools()
        self.assertIn("nikto", out)
        self.assertIn("sqlmap", out)
        self.assertNotIn("nmap", out)

    def test_include_optional(self):
        out = select_tools(include_optional=True)
        self.assertIn("nmap", out)


class RunInstallerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lockfile = os.path.join(self.tmp.name, "tools.lock.json")
        self.printed = []

    def tearDown(self):
        self.tmp.cleanup()

    def _printer(self, msg):
        self.printed.append(msg)

    def test_dry_run_writes_lockfile_and_runs_nothing(self):
        with patch("shutil.which", return_value=None), \
             patch("subprocess.run") as mock_run, \
             patch("config.tool_installer.detect_platform",
                    return_value=_plat()):
            results, plat = run_installer(
                only=["sqlmap"], dry_run=True,
                lockfile=self.lockfile, printer=self._printer)
        mock_run.assert_not_called()
        self.assertTrue(os.path.exists(self.lockfile))
        out = "\n".join(self.printed)
        self.assertIn("DRY-RUN", out)
        self.assertIn("sqlmap", out)

    def test_dry_run_shows_pinned_pip_command_in_plan(self):
        with patch("shutil.which", return_value=None), \
             patch("config.tool_installer.detect_platform",
                    return_value=_plat()):
            run_installer(only=["sqlmap"], dry_run=True,
                          lockfile=self.lockfile, printer=self._printer)
        out = "\n".join(self.printed)
        self.assertIn(f"sqlmap=={PINNED_VERSIONS['sqlmap']}", out)

    def test_confirm_without_valid_sudo_falls_back_for_sudo_steps(self):
        # nikto needs sudo apt, but sudo -n -v fails → installer must NOT
        # actually invoke apt.
        with patch("shutil.which", side_effect=lambda c: "/usr/bin/sudo"
                       if c == "sudo" else None), \
             patch("subprocess.run") as mock_run, \
             patch("config.tool_installer._sudo_valid", return_value=False), \
             patch("config.tool_installer.detect_platform",
                    return_value=_plat()):
            run_installer(only=["nikto"], dry_run=False,
                          lockfile=self.lockfile, printer=self._printer)
        # subprocess.run should have been called 0 times for apt
        # (the install step is forced into dry-run mode).
        for call in mock_run.call_args_list:
            argv = call.args[0] if call.args else []
            self.assertNotIn("apt-get", argv,
                             f"installer ran apt without sudo: {argv}")
        out = "\n".join(self.printed)
        self.assertIn("sudo", out.lower())

    def test_lockfile_records_platform(self):
        with patch("shutil.which", return_value=None), \
             patch("config.tool_installer.detect_platform",
                    return_value=_plat(distro="ubuntu", pkg_mgr="apt")):
            run_installer(only=["sqlmap"], dry_run=True,
                          lockfile=self.lockfile, printer=self._printer)
        data = json.loads(open(self.lockfile).read())
        self.assertEqual(data["platform"]["distro"], "ubuntu")
        self.assertEqual(data["platform"]["pkg_mgr"], "apt")

    def test_already_installed_is_marked_as_such(self):
        with patch("shutil.which", return_value="/usr/local/bin/sqlmap"), \
             patch("config.tool_paths.ToolPathValidator._version",
                    return_value="1.8.10"), \
             patch("config.tool_installer.detect_platform",
                    return_value=_plat()):
            results, _ = run_installer(only=["sqlmap"], dry_run=True,
                                        lockfile=self.lockfile,
                                        printer=self._printer)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].already_installed)
        out = "\n".join(self.printed)
        self.assertIn("already installed", out)


class PlatformDetectionTests(unittest.TestCase):
    def test_detect_returns_required_keys(self):
        plat = tool_installer.detect_platform()
        for key in ("system", "distro", "pkg_mgr", "python",
                    "has_sudo", "has_go"):
            self.assertIn(key, plat)

    def test_linux_distro_read_from_os_release(self):
        # Just verify the helper doesn't crash on this machine.
        distro = tool_installer._read_linux_distro()
        self.assertIsInstance(distro, str)


if __name__ == "__main__":
    unittest.main()
