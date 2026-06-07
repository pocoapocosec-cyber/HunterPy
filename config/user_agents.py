"""User-agent selection for HunterPy.

The default UA is **honest disclosure** (``HunterPy/2.0
(+authorized-testing)``). That's deliberate: a scanner whose traffic
shows up in the blue team's logs as itself is the scanner that pentest
firms can defend in an SOW review. The override here exists for the
legitimate cases:

  * **WAF bypass testing** — does the WAF block ``HunterPy`` but pass
    ``Mozilla/5.0 ... Chrome/...``? That's a finding.
  * **UA-conditional rendering** — does the app serve a different SPA
    bundle to iOS Safari vs desktop Chrome? Most modern apps do.
  * **Bot-detection evaluation** — rotating UAs while the target's WAF
    rules are dialed up to "challenge" gives you a clean view of which
    UAs the SOC actually trusts.

Rotation strategies:

  * ``static``               — one UA for the whole scan.
  * ``rotate-random``        — pick uniformly at random per request.
  * ``rotate-sequential``    — round-robin through the pool per request.

The pool comes from (in order of precedence):

  1. ``--user-agent-pool "A" "B" ...`` — explicit list.
  2. ``--user-agent-file PATH``        — one per line, ``#`` comments allowed.
  3. ``--user-agent-preset NAME``      — built-in preset by name.
  4. ``--user-agent STRING``           — single string (resolves to a 1-item pool).
  5. The hard-coded default.

Note on impersonating bots (Googlebot/Bingbot/etc.):

Spoofing search-engine bots can violate Google's webmaster guidelines
and will get you flagged by mature WAFs / bot-management products. We
include those presets because they have legitimate uses (e.g.
comparing crawl-time vs user-time responses, finding cloaked content)
but they're labelled ``noisy_impersonation`` in the preset metadata so
the operator knows what they're doing.
"""
from __future__ import annotations

import itertools
import logging
import os
import random
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence


log = logging.getLogger("hunterpy.ua")


DEFAULT_USER_AGENT = "HunterPy/2.0 (+authorized-testing)"


# ---------------------------------------------------------------------------
# Preset library. Strings are intentionally NOT formatted with the latest
# Chrome major-version "of the day" — they're stable strings we test
# against. Bump them deliberately, not automatically.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class UAPreset:
    name: str
    description: str
    user_agents: List[str]
    category: str = "browser"   # "browser" | "tool" | "noisy_impersonation"


_CHROME_WIN = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36")
_CHROME_MAC = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36")
_CHROME_LINUX = ("Mozilla/5.0 (X11; Linux x86_64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/124.0.0.0 Safari/537.36")
_FIREFOX_WIN = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) "
                 "Gecko/20100101 Firefox/127.0")
_FIREFOX_LINUX = ("Mozilla/5.0 (X11; Linux x86_64; rv:127.0) "
                   "Gecko/20100101 Firefox/127.0")
_SAFARI_MAC = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.5 Safari/605.1.15")
_SAFARI_IOS = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.5 Mobile/15E148 Safari/604.1")
_CHROME_ANDROID = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Mobile Safari/537.36")
_EDGE_WIN = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0")

_GOOGLEBOT = ("Mozilla/5.0 (compatible; Googlebot/2.1; "
               "+http://www.google.com/bot.html)")
_BINGBOT = ("Mozilla/5.0 (compatible; bingbot/2.0; "
             "+http://www.bing.com/bingbot.htm)")


PRESETS: Dict[str, UAPreset] = {
    "default": UAPreset(
        name="default",
        description="Honest disclosure — identifies HunterPy in target logs",
        user_agents=[DEFAULT_USER_AGENT],
        category="tool",
    ),
    "chrome-windows": UAPreset(
        name="chrome-windows",
        description="Chrome 124 on Windows 10/11 x64",
        user_agents=[_CHROME_WIN],
    ),
    "chrome-mac": UAPreset(
        name="chrome-mac",
        description="Chrome 124 on macOS",
        user_agents=[_CHROME_MAC],
    ),
    "chrome-linux": UAPreset(
        name="chrome-linux",
        description="Chrome 124 on Linux x86_64",
        user_agents=[_CHROME_LINUX],
    ),
    "firefox-windows": UAPreset(
        name="firefox-windows",
        description="Firefox 127 on Windows",
        user_agents=[_FIREFOX_WIN],
    ),
    "firefox-linux": UAPreset(
        name="firefox-linux",
        description="Firefox 127 on Linux",
        user_agents=[_FIREFOX_LINUX],
    ),
    "safari-mac": UAPreset(
        name="safari-mac",
        description="Safari 17 on macOS",
        user_agents=[_SAFARI_MAC],
    ),
    "safari-ios": UAPreset(
        name="safari-ios",
        description="Mobile Safari on iOS 17",
        user_agents=[_SAFARI_IOS],
    ),
    "chrome-android": UAPreset(
        name="chrome-android",
        description="Chrome on Android 14 (Pixel)",
        user_agents=[_CHROME_ANDROID],
    ),
    "edge-windows": UAPreset(
        name="edge-windows",
        description="Edge 124 on Windows",
        user_agents=[_EDGE_WIN],
    ),

    # Multi-UA presets — designed for rotation
    "desktop-browsers": UAPreset(
        name="desktop-browsers",
        description="Chrome / Firefox / Safari / Edge on Windows / macOS / Linux",
        user_agents=[_CHROME_WIN, _CHROME_MAC, _CHROME_LINUX,
                     _FIREFOX_WIN, _FIREFOX_LINUX,
                     _SAFARI_MAC, _EDGE_WIN],
    ),
    "mobile-browsers": UAPreset(
        name="mobile-browsers",
        description="Mobile Safari (iOS) + Chrome (Android)",
        user_agents=[_SAFARI_IOS, _CHROME_ANDROID],
    ),
    "all-browsers": UAPreset(
        name="all-browsers",
        description="Every desktop + mobile browser preset combined",
        user_agents=[_CHROME_WIN, _CHROME_MAC, _CHROME_LINUX,
                     _FIREFOX_WIN, _FIREFOX_LINUX,
                     _SAFARI_MAC, _SAFARI_IOS, _CHROME_ANDROID, _EDGE_WIN],
    ),

    # Honest tool fingerprints — also useful for WAF testing
    "curl": UAPreset(
        name="curl",
        description="curl/8.8.0 — often blocked by basic WAFs",
        user_agents=["curl/8.8.0"],
        category="tool",
    ),
    "wget": UAPreset(
        name="wget",
        description="Wget/1.21.4",
        user_agents=["Wget/1.21.4"],
        category="tool",
    ),

    # Bot impersonation — flagged as noisy_impersonation. Use carefully.
    "googlebot": UAPreset(
        name="googlebot",
        description="(IMPERSONATION) Googlebot 2.1 — violates Google ToS, "
                     "blocked by mature WAFs by IP-pinning the real "
                     "Googlebot ranges. Use only when explicitly testing "
                     "for cloaking or bot-allowlist misconfigurations.",
        user_agents=[_GOOGLEBOT],
        category="noisy_impersonation",
    ),
    "bingbot": UAPreset(
        name="bingbot",
        description="(IMPERSONATION) Bingbot 2.0 — same caveats as googlebot.",
        user_agents=[_BINGBOT],
        category="noisy_impersonation",
    ),
}


def list_presets() -> List[Dict[str, str]]:
    """Return a list of dicts suitable for `--list-user-agents` output."""
    return [
        {
            "name":        p.name,
            "category":    p.category,
            "count":       str(len(p.user_agents)),
            "description": p.description,
        }
        for p in PRESETS.values()
    ]


def resolve_preset(name: str) -> UAPreset:
    if name not in PRESETS:
        raise ValueError(
            f"unknown user-agent preset {name!r} — valid: "
            f"{sorted(PRESETS.keys())}")
    return PRESETS[name]


# ---------------------------------------------------------------------------
def load_pool_file(path: str) -> List[str]:
    """Load a UA pool from a file (one per line, `#` comments allowed).

    Raises ``ValueError`` if the file exists but contains no usable UAs.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"user-agent file not found: {path}")
    out: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            out.append(s)
    if not out:
        raise ValueError(f"user-agent file {path!r} contained no entries")
    return out


# ---------------------------------------------------------------------------
class UserAgentSelector:
    """Thread-safe per-request user-agent picker.

    Strategy is fixed at construction time. Call ``.next()`` for each
    request that needs a UA. ``.current()`` returns the "primary" UA
    (first in the pool) for places that need a single deterministic
    value (e.g. logging the configured UA in the scan banner).
    """

    STRATEGIES = ("static", "rotate-random", "rotate-sequential")

    def __init__(self, pool: Sequence[str], strategy: str = "static",
                 *, rng: Optional[random.Random] = None):
        if not pool:
            raise ValueError("user-agent pool cannot be empty")
        if strategy not in self.STRATEGIES:
            raise ValueError(
                f"unknown user-agent strategy {strategy!r} — valid: "
                f"{self.STRATEGIES}")
        self._pool: List[str] = list(pool)
        self._strategy = strategy
        self._rng = rng or random.Random()
        self._lock = threading.Lock()
        # Sequential rotation uses an itertools.cycle wrapped in the lock
        self._cycle = itertools.cycle(self._pool)

    # ---- public API ----
    @property
    def pool(self) -> List[str]:
        return list(self._pool)

    @property
    def strategy(self) -> str:
        return self._strategy

    def current(self) -> str:
        """The deterministic 'primary' UA. Always pool[0]."""
        return self._pool[0]

    def next(self) -> str:
        """Pick the next UA according to the configured strategy."""
        if self._strategy == "static":
            return self._pool[0]
        if self._strategy == "rotate-random":
            return self._rng.choice(self._pool)
        if self._strategy == "rotate-sequential":
            with self._lock:
                return next(self._cycle)
        # Defensive — STRATEGIES is validated at __init__.
        raise RuntimeError(f"unhandled strategy: {self._strategy}")

    def describe(self) -> str:
        """One-line summary for log / banner output."""
        return (f"strategy={self._strategy}  pool={len(self._pool)}  "
                f"primary={self._pool[0][:60]}"
                + ("..." if len(self._pool[0]) > 60 else ""))

    # ---- factory ----
    @classmethod
    def from_args(cls, *,
                  single: Optional[str] = None,
                  preset: Optional[str] = None,
                  pool: Optional[Sequence[str]] = None,
                  pool_file: Optional[str] = None,
                  strategy: str = "static") -> "UserAgentSelector":
        """Resolve sources in the documented precedence order and build a
        selector. Raises ``ValueError`` on bad input."""
        resolved: List[str] = []
        if pool:
            resolved = list(pool)
        elif pool_file:
            resolved = load_pool_file(pool_file)
        elif preset:
            resolved = list(resolve_preset(preset).user_agents)
        elif single:
            resolved = [single]
        else:
            resolved = [DEFAULT_USER_AGENT]

        if strategy != "static" and len(resolved) <= 1:
            log.warning(
                "user-agent rotation strategy %r requested but pool only "
                "has %d entry — collapsing to 'static'",
                strategy, len(resolved))
            strategy = "static"
        return cls(resolved, strategy=strategy)
