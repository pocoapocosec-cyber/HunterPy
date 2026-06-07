"""Tool installer — transparent, pinned, dry-run by default.

Design principles (read these before "improving" the installer):

  * **Dry-run by default.** The installer prints exactly what it would
    do and exits zero. The operator has to pass ``--install-tools-confirm``
    to actually execute anything.
  * **No silent privilege escalation.** If a step needs sudo, the
    installer prints ``sudo -n -v`` first; if that fails, it refuses to
    run apt/brew/pacman steps and prints what the operator should do
    manually.
  * **Pinned versions for everything we ship binaries for.** Anything
    fetched outside a distro package manager (today: nothing — see
    "Why we don't ship Go binaries" below) MUST have a SHA-256 in this
    file. No ``go install ...@latest``. No ``curl | bash``.
  * **Idempotent.** Re-running the installer with everything already on
    PATH prints a clean "nothing to do" and writes the lockfile anyway.
  * **Reproducible.** After a successful run, ``tools.lock.json``
    records the tool name, the install method, the resolved version,
    and the absolute path. CI can diff this between runs.
  * **Platform-aware.** We detect (linux+apt | linux+pacman | linux+apk
    | macos+brew | windows | unknown). For unknown platforms we still
    print the plan, just with a "manual" install method.

### Why we don't auto-`go install` the Go-toolchain tools

`ffuf`, `gobuster`, and `nuclei` are all Go projects whose canonical
install path is `go install github.com/...@<version>`. That's:

  * a hard dependency on the Go toolchain being present
  * unsigned binaries pulled from GitHub HEAD by default
  * version-skew between operator workstations

Distro packages exist for `ffuf` and `gobuster` on Debian/Ubuntu and
Homebrew. `nuclei` ships binary releases on GitHub with SHA-256 sums
published — that's a future installer method we'd add with checksum
verification, but it's not in v2.4. For now, if a Go tool isn't in the
distro repo, the installer prints the exact `go install` command and
refuses to run it itself.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple


log = logging.getLogger("hunterpy.installer")


# --------------------------------------------------------------------------
# Pinned version table.
#
# These versions are what we've tested against. Bumping any of them
# requires re-running the full test suite. If you bump a version, update
# the comment with the date and your initials.
# --------------------------------------------------------------------------
PINNED_VERSIONS: Dict[str, str] = {
    # Python packages (resolved via pip; pip itself verifies wheel hashes
    # against PyPI's index).
    "sqlmap":  "1.8.10",     # pinned 2026-06-07
    "wfuzz":   "3.1.0",      # pinned 2026-06-07

    # Go modules (NOT auto-installed — we print the command only).
    "gobuster": "v3.6.0",    # pinned 2026-06-07
    "ffuf":     "v2.1.0",    # pinned 2026-06-07
    "nuclei":   "v3.2.7",    # pinned 2026-06-07

    # Distro packages — version comes from the distro repo. We record
    # what we tested against for reproducibility but won't pin the
    # actual install (that would require holding back a package).
    "nikto":   ">=2.5.0",
    "hydra":   ">=9.4",
    "nmap":    ">=7.94",
    "curl":    ">=7.81",
    "whatweb": ">=0.5.5",
}


# --------------------------------------------------------------------------
# Tool installation plans, keyed by (tool_name, platform_method).
#
# Each plan is a list of (description, argv) pairs. The installer prints
# every step, then either dry-runs or executes them in order. A step
# starting with ["sudo", ...] requires `sudo -n -v` to succeed first.
# --------------------------------------------------------------------------

@dataclass
class InstallStep:
    description: str
    argv: List[str]
    needs_sudo: bool = False
    # Optional probe to verify the step succeeded (e.g. `which nikto`)
    verify_cmd: Optional[List[str]] = None


@dataclass
class InstallPlan:
    tool: str
    method: str               # "apt" | "brew" | "pip" | "pacman" | "apk" | "manual"
    pinned: Optional[str]
    steps: List[InstallStep] = field(default_factory=list)
    notes: str = ""
    # If True, this plan is documentation-only (we WILL NOT execute it
    # even with --install-tools-confirm). Used for Go modules.
    manual_only: bool = False


# --------------------------------------------------------------------------
# Platform detection
# --------------------------------------------------------------------------
def detect_platform() -> Dict[str, Any]:
    """Return a dict describing the current platform + package manager.

    Keys:
      system    : "linux" | "darwin" | "windows" | "unknown"
      distro    : best-effort distro id on linux (debian/ubuntu/arch/alpine/...)
      pkg_mgr   : "apt" | "brew" | "pacman" | "apk" | "dnf" | None
      python    : sys.executable
      has_sudo  : bool — sudo binary on PATH
      has_go    : bool — go binary on PATH
    """
    sysname = platform.system().lower()
    if sysname not in ("linux", "darwin", "windows"):
        sysname = "unknown"

    distro = ""
    pkg_mgr = None
    if sysname == "linux":
        distro = _read_linux_distro()
        for mgr in ("apt-get", "apt", "pacman", "apk", "dnf", "yum"):
            if shutil.which(mgr):
                pkg_mgr = mgr.replace("apt-get", "apt")
                break
    elif sysname == "darwin":
        if shutil.which("brew"):
            pkg_mgr = "brew"
    # windows: no auto-installer this release; we just print "manual"

    return {
        "system":   sysname,
        "distro":   distro,
        "pkg_mgr":  pkg_mgr,
        "python":   sys.executable,
        "has_sudo": shutil.which("sudo") is not None,
        "has_go":   shutil.which("go") is not None,
    }


def _read_linux_distro() -> str:
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("ID="):
                    return line.strip().split("=", 1)[1].strip('"')
    except OSError:
        pass
    return ""


# --------------------------------------------------------------------------
# Plan builders — one per (tool, package manager).
# --------------------------------------------------------------------------
def _plan_apt(tool: str, pkg: str, *, pinned: Optional[str] = None) -> InstallPlan:
    return InstallPlan(
        tool=tool, method="apt", pinned=pinned,
        steps=[
            InstallStep(
                description=f"Install {pkg} via apt",
                argv=["sudo", "apt-get", "install", "-y", pkg],
                needs_sudo=True,
                verify_cmd=["which", tool],
            ),
        ],
        notes=f"Distro package; actual version follows {pkg} in your repo.",
    )


def _plan_brew(tool: str, pkg: str, *, pinned: Optional[str] = None) -> InstallPlan:
    return InstallPlan(
        tool=tool, method="brew", pinned=pinned,
        steps=[
            InstallStep(
                description=f"Install {pkg} via Homebrew",
                argv=["brew", "install", pkg],
                verify_cmd=["which", tool],
            ),
        ],
    )


def _plan_pacman(tool: str, pkg: str, *, pinned: Optional[str] = None) -> InstallPlan:
    return InstallPlan(
        tool=tool, method="pacman", pinned=pinned,
        steps=[
            InstallStep(
                description=f"Install {pkg} via pacman",
                argv=["sudo", "pacman", "-S", "--noconfirm", pkg],
                needs_sudo=True,
                verify_cmd=["which", tool],
            ),
        ],
    )


def _plan_apk(tool: str, pkg: str, *, pinned: Optional[str] = None) -> InstallPlan:
    return InstallPlan(
        tool=tool, method="apk", pinned=pinned,
        steps=[
            InstallStep(
                description=f"Install {pkg} via apk",
                argv=["sudo", "apk", "add", pkg],
                needs_sudo=True,
                verify_cmd=["which", tool],
            ),
        ],
    )


def _plan_pip(tool: str, package_spec: str, *, pinned: Optional[str] = None) -> InstallPlan:
    return InstallPlan(
        tool=tool, method="pip", pinned=pinned,
        steps=[
            InstallStep(
                description=f"Install {package_spec} via pip",
                argv=[sys.executable, "-m", "pip", "install", "--user", package_spec],
                verify_cmd=["which", tool],
            ),
        ],
        notes="Installs to the user site (no sudo). Add `python -m site --user-base`/bin to PATH.",
    )


def _plan_go_manual(tool: str, import_path: str, pinned: str) -> InstallPlan:
    """Documentation-only plan for Go tools. We print the command but
    never execute it — see the module docstring."""
    return InstallPlan(
        tool=tool, method="manual", pinned=pinned,
        manual_only=True,
        steps=[
            InstallStep(
                description=f"(MANUAL) Install {tool}@{pinned} via Go toolchain",
                argv=["go", "install", f"{import_path}@{pinned}"],
                verify_cmd=["which", tool],
            ),
        ],
        notes=("Go binaries are NOT auto-installed (no checksum verification "
               "for `go install`). Run this command yourself, OR install the "
               "distro package if one exists for your platform."),
    )


def _plan_unsupported(tool: str, reason: str) -> InstallPlan:
    return InstallPlan(
        tool=tool, method="manual", pinned=PINNED_VERSIONS.get(tool),
        manual_only=True,
        notes=reason,
    )


# --------------------------------------------------------------------------
# Tool catalogue — maps tool → per-method plan builders.
# --------------------------------------------------------------------------
def build_plan(tool: str, plat: Dict[str, Any]) -> InstallPlan:
    """Return the best InstallPlan for `tool` on the detected platform."""
    pkg_mgr = plat["pkg_mgr"]
    pinned = PINNED_VERSIONS.get(tool)

    # Tools available via distro/brew packages in most cases
    distro_pkg_map = {
        "nikto":   {"apt": "nikto",   "brew": "nikto",   "pacman": "nikto",   "apk": None},
        "hydra":   {"apt": "hydra",   "brew": "hydra",   "pacman": "hydra",   "apk": "hydra"},
        "nmap":    {"apt": "nmap",    "brew": "nmap",    "pacman": "nmap",    "apk": "nmap"},
        "curl":    {"apt": "curl",    "brew": "curl",    "pacman": "curl",    "apk": "curl"},
        "whatweb": {"apt": "whatweb", "brew": "whatweb", "pacman": None,      "apk": None},
        # gobuster + ffuf ARE in modern Debian/Ubuntu repos
        "gobuster": {"apt": "gobuster", "brew": "gobuster", "pacman": "gobuster", "apk": None},
        "ffuf":     {"apt": "ffuf",     "brew": "ffuf",     "pacman": None,       "apk": None},
    }

    # Python tools always go through pip with a pinned version
    pip_specs = {
        "sqlmap": f"sqlmap=={PINNED_VERSIONS['sqlmap']}",
        "wfuzz":  f"wfuzz=={PINNED_VERSIONS['wfuzz']}",
    }

    # Go-module-only tools (no good distro path)
    go_imports = {
        "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
    }

    if tool in pip_specs:
        return _plan_pip(tool, pip_specs[tool], pinned=pinned)

    if tool in distro_pkg_map and pkg_mgr in distro_pkg_map[tool]:
        pkg = distro_pkg_map[tool][pkg_mgr]
        if pkg:
            if pkg_mgr == "apt":
                return _plan_apt(tool, pkg, pinned=pinned)
            if pkg_mgr == "brew":
                return _plan_brew(tool, pkg, pinned=pinned)
            if pkg_mgr == "pacman":
                return _plan_pacman(tool, pkg, pinned=pinned)
            if pkg_mgr == "apk":
                return _plan_apk(tool, pkg, pinned=pinned)

    # No distro path — fall back to Go-manual or print "unsupported"
    if tool in go_imports:
        return _plan_go_manual(tool, go_imports[tool], pinned or "latest")
    if tool in distro_pkg_map:
        return _plan_unsupported(
            tool,
            f"No installation plan for {tool} on {plat['system']}/{pkg_mgr or 'none'}. "
            f"Install manually: see https://github.com/search?q={tool}",
        )
    return _plan_unsupported(tool, f"Unknown tool: {tool}")


# --------------------------------------------------------------------------
# Executor
# --------------------------------------------------------------------------
@dataclass
class StepResult:
    description: str
    argv: List[str]
    ran: bool
    exit_code: Optional[int]
    stdout_tail: str = ""
    stderr_tail: str = ""
    duration_ms: int = 0
    skipped_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class PlanResult:
    tool: str
    method: str
    pinned: Optional[str]
    already_installed: bool
    skipped: bool
    success: bool
    steps: List[StepResult] = field(default_factory=list)
    resolved_version: Optional[str] = None
    resolved_path: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        return d


def _run_step(step: InstallStep, *, dry_run: bool,
              has_sudo: bool) -> StepResult:
    if step.needs_sudo and not has_sudo:
        return StepResult(
            description=step.description, argv=step.argv, ran=False,
            exit_code=None,
            skipped_reason="step needs sudo but `sudo` is not on PATH",
        )
    if dry_run:
        return StepResult(
            description=step.description, argv=step.argv, ran=False,
            exit_code=None, skipped_reason="dry-run",
        )
    t0 = time.time()
    try:
        proc = subprocess.run(
            step.argv, capture_output=True, text=True, timeout=600,
        )
        elapsed = int((time.time() - t0) * 1000)
        return StepResult(
            description=step.description, argv=step.argv, ran=True,
            exit_code=proc.returncode,
            stdout_tail=(proc.stdout or "").strip().splitlines()[-1][:200]
                if proc.stdout else "",
            stderr_tail=(proc.stderr or "").strip().splitlines()[-1][:200]
                if proc.stderr else "",
            duration_ms=elapsed,
        )
    except FileNotFoundError as e:
        return StepResult(
            description=step.description, argv=step.argv, ran=False,
            exit_code=None,
            skipped_reason=f"executable not found: {e}",
        )
    except subprocess.TimeoutExpired:
        return StepResult(
            description=step.description, argv=step.argv, ran=False,
            exit_code=None,
            skipped_reason="step timed out after 600s",
        )


def _sudo_valid() -> bool:
    """True if `sudo -n -v` succeeds (i.e. credentials are already cached)."""
    if not shutil.which("sudo"):
        return False
    try:
        r = subprocess.run(["sudo", "-n", "-v"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def execute_plan(plan: InstallPlan, *, dry_run: bool,
                 has_sudo: bool) -> PlanResult:
    """Execute (or dry-run) a single tool's plan."""
    from config.tool_paths import REQUIRED_TOOLS, OPTIONAL_TOOLS, ToolPathValidator

    info = REQUIRED_TOOLS.get(plan.tool) or OPTIONAL_TOOLS.get(plan.tool)
    cmd = info["cmd"] if info else plan.tool

    # Already installed?
    existing = shutil.which(cmd)
    if existing:
        version = ToolPathValidator._version(cmd)
        return PlanResult(
            tool=plan.tool, method=plan.method, pinned=plan.pinned,
            already_installed=True, skipped=True, success=True,
            resolved_version=version, resolved_path=existing,
            notes="already on PATH; skipped",
        )

    if plan.manual_only:
        # We print the steps but record them as skipped — never auto-run.
        steps = [StepResult(description=s.description, argv=s.argv,
                             ran=False, exit_code=None,
                             skipped_reason="manual-only plan")
                 for s in plan.steps]
        return PlanResult(
            tool=plan.tool, method=plan.method, pinned=plan.pinned,
            already_installed=False, skipped=True, success=False,
            steps=steps, notes=plan.notes,
        )

    # Run each step, abort on first failure.
    step_results: List[StepResult] = []
    for step in plan.steps:
        r = _run_step(step, dry_run=dry_run, has_sudo=has_sudo)
        step_results.append(r)
        if r.ran and r.exit_code not in (0, None):
            break

    if dry_run:
        return PlanResult(
            tool=plan.tool, method=plan.method, pinned=plan.pinned,
            already_installed=False, skipped=True, success=False,
            steps=step_results, notes="dry-run: nothing executed",
        )

    # Re-check whether the tool is now on PATH. We also probe the common
    # "user-site" install locations so a `pip install --user` that just
    # succeeded but landed in a PATH-less ~/.local/bin still reports as
    # installed (with a hint about updating PATH).
    new_path = shutil.which(cmd)
    if not new_path:
        new_path = _probe_user_site_paths(cmd)

    if new_path:
        path_hint = ""
        if not shutil.which(cmd):
            path_hint = (f" — but {os.path.dirname(new_path)} is not on "
                          f"your PATH; add it to use {cmd} directly")
        return PlanResult(
            tool=plan.tool, method=plan.method, pinned=plan.pinned,
            already_installed=False, skipped=False, success=True,
            steps=step_results,
            resolved_version=ToolPathValidator._version(new_path),
            resolved_path=new_path,
            notes=("install succeeded" + path_hint) if path_hint else "",
        )
    # Distinguish "every step actually ran and exited zero, but the
    # binary still isn't visible" from "we never got to run the steps".
    any_ran = any(s.ran for s in step_results)
    any_nonzero = any(s.ran and s.exit_code not in (0, None)
                       for s in step_results)
    if not any_ran:
        note = "no install steps were executed (check sudo / dry-run state)"
    elif any_nonzero:
        note = "install step failed — see stderr_tail in result"
    else:
        note = ("install steps reported success but tool is not on PATH — "
                "check ~/.local/bin (pip --user) or $HOME/go/bin (Go modules)")
    return PlanResult(
        tool=plan.tool, method=plan.method, pinned=plan.pinned,
        already_installed=False, skipped=False, success=False,
        steps=step_results, notes=note,
    )


def _probe_user_site_paths(cmd: str) -> Optional[str]:
    """Look for `cmd` in the common user-install locations that aren't
    necessarily on PATH (pip --user, go install)."""
    candidates: List[str] = []
    # pip --user
    try:
        import site
        user_base = site.getuserbase()
        candidates.append(os.path.join(user_base, "bin", cmd))
    except Exception:
        pass
    # Go modules
    gopath = os.environ.get("GOPATH") or os.path.expanduser("~/go")
    candidates.append(os.path.join(gopath, "bin", cmd))
    # ~/.local/bin as a fallback
    candidates.append(os.path.expanduser(f"~/.local/bin/{cmd}"))
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


# --------------------------------------------------------------------------
# Lockfile
# --------------------------------------------------------------------------
LOCKFILE_VERSION = 1


def write_lockfile(path: str, plat: Dict[str, Any],
                   results: List[PlanResult]) -> None:
    payload = {
        "lockfile_version": LOCKFILE_VERSION,
        "generated_at":     datetime.now(tz=timezone.utc).isoformat(),
        "platform":         plat,
        "tools": [
            {
                "name":               r.tool,
                "method":             r.method,
                "pinned":             r.pinned,
                "already_installed":  r.already_installed,
                "success":            r.success,
                "resolved_version":   r.resolved_version,
                "resolved_path":      r.resolved_path,
                "notes":              r.notes,
            }
            for r in results
        ],
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def read_lockfile(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# Top-level orchestrator (called from main.py)
# --------------------------------------------------------------------------
def select_tools(only: Optional[Sequence[str]] = None,
                 include_optional: bool = False) -> List[str]:
    from config.tool_paths import REQUIRED_TOOLS, OPTIONAL_TOOLS
    if only:
        return list(only)
    out = list(REQUIRED_TOOLS.keys())
    if include_optional:
        out.extend(OPTIONAL_TOOLS.keys())
    return out


def run_installer(*,
                  only: Optional[Sequence[str]] = None,
                  include_optional: bool = False,
                  dry_run: bool = True,
                  lockfile: str = "tools.lock.json",
                  printer=print) -> Tuple[List[PlanResult], Dict[str, Any]]:
    """Build plans, print them, optionally execute, write the lockfile.

    Returns ``(results, platform)``. The caller decides the exit code.
    """
    plat = detect_platform()
    printer("")
    printer("HunterPy tool installer")
    printer("=" * 60)
    printer(f"  system   : {plat['system']} ({plat['distro'] or 'n/a'})")
    printer(f"  pkg_mgr  : {plat['pkg_mgr'] or 'none detected'}")
    printer(f"  python   : {plat['python']}")
    printer(f"  sudo     : {'yes' if plat['has_sudo'] else 'no'}")
    printer(f"  go       : {'yes' if plat['has_go'] else 'no'}")
    printer(f"  mode     : {'DRY-RUN' if dry_run else 'EXECUTE'}")
    printer("")

    # Pre-flight: if anything in the plan needs sudo and we're executing,
    # require a valid sudo session (no silent password prompts).
    needs_sudo_anywhere = False
    tools = select_tools(only, include_optional=include_optional)
    plans = [build_plan(t, plat) for t in tools]
    for p in plans:
        if any(s.needs_sudo for s in p.steps):
            needs_sudo_anywhere = True
            break

    sudo_ok = True
    if needs_sudo_anywhere and not dry_run:
        sudo_ok = _sudo_valid()
        if not sudo_ok:
            printer("[!] Some steps require sudo, but `sudo -n -v` failed.")
            printer("    Run `sudo -v` in this terminal first, then re-run "
                    "the installer. The installer will NEVER prompt for a "
                    "password itself.")
            printer("    Falling back to dry-run for sudo-requiring steps.")
            printer("")

    # Print every plan up-front so the operator sees the whole thing
    # before any command runs.
    printer("Plan:")
    for p in plans:
        printer(f"  - {p.tool:<10s} method={p.method:<7s} "
                f"pinned={p.pinned or '-':<10s} "
                f"{'(manual-only)' if p.manual_only else ''}")
        for s in p.steps:
            sudo_tag = " [needs sudo]" if s.needs_sudo else ""
            printer(f"        $ {' '.join(s.argv)}{sudo_tag}")
        if p.notes:
            printer(f"        note: {p.notes}")
    printer("")

    if dry_run:
        printer("Dry-run: nothing executed. Re-run with "
                "--install-tools-confirm to actually install.")
        printer("")

    # Execute
    results: List[PlanResult] = []
    for p in plans:
        # If sudo is required for THIS plan but unavailable, force dry-run
        # for just this plan.
        plan_needs_sudo = any(s.needs_sudo for s in p.steps)
        effective_dry = dry_run or (plan_needs_sudo and not sudo_ok and not dry_run)
        r = execute_plan(p, dry_run=effective_dry, has_sudo=plat["has_sudo"])
        results.append(r)

        # Per-tool status line
        if r.already_installed:
            printer(f"  ✓ {p.tool:<10s} already installed "
                    f"({r.resolved_version}) at {r.resolved_path}")
        elif r.skipped:
            why = r.notes or "skipped"
            printer(f"  ~ {p.tool:<10s} skipped — {why}")
        elif r.success:
            printer(f"  ✓ {p.tool:<10s} installed "
                    f"({r.resolved_version}) at {r.resolved_path}")
        else:
            printer(f"  ✗ {p.tool:<10s} failed — {r.notes or 'unknown reason'}")
            for s in r.steps:
                if s.exit_code not in (None, 0) and s.ran:
                    printer(f"        step `{' '.join(s.argv)}` "
                            f"exited {s.exit_code}: {s.stderr_tail}")
                elif s.skipped_reason:
                    printer(f"        skipped: {s.skipped_reason}")

    # Write the lockfile regardless of outcome — it's a record of what
    # we found, even if we didn't change anything.
    try:
        write_lockfile(lockfile, plat, results)
        printer(f"\nWrote lockfile: {lockfile}")
    except OSError as e:
        printer(f"\n[!] Could not write lockfile {lockfile}: {e}")

    return results, plat
