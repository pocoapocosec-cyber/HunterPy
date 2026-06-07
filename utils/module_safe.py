"""Standard error-handling decorator for module ``run()`` methods.

Before this decorator existed, ~20 modules each handled exceptions
differently:

  * some had ``try: ... except Exception: pass`` (silent loss)
  * some bubbled (one bad module → whole scan dies)
  * some logged at WARNING, others at ERROR, others not at all
  * some skipped on missing tools, others crashed with FileNotFoundError

That inconsistency made the engine's ``_safe_run`` catch-all the de
facto policy enforcer — which is exactly the wrong place. This
decorator gives modules a single, declarative policy:

    @module_safe(fallback="skip", log_level="warning")
    def run(self):
        ...

Behaviour:
  * ``fallback="skip"``  — catch any exception, return a "skipped"
    module dict so the engine treats it like any other no-op.
  * ``fallback="empty"`` — return ``{"module": ..., "findings": []}``.
    Use for modules where "no findings" is a legitimate outcome.
  * ``fallback="raise"`` — re-raise after logging. Use only for fatal
    pre-conditions (no target, no auth, etc.).
  * ``log_level``        — "warning" (default), "error", or "info".

The exception is recorded in the returned dict's ``error`` field so the
engine can surface it in the report without having to dig through logs.
"""
from __future__ import annotations

import functools
import logging
import traceback
from typing import Any, Callable, Dict


log = logging.getLogger("hunterpy.module_safe")


VALID_FALLBACKS = ("skip", "empty", "raise")
VALID_LOG_LEVELS = ("debug", "info", "warning", "error")


def module_safe(*,
                fallback: str = "skip",
                log_level: str = "warning") -> Callable:
    """Decorator factory. Wraps a module method (typically ``run``).

    The wrapped method is expected to either return a dict or raise.
    The decorator turns any unhandled exception into a consistent
    fallback dict + a log entry at the configured level.
    """
    if fallback not in VALID_FALLBACKS:
        raise ValueError(f"fallback must be one of {VALID_FALLBACKS}")
    if log_level not in VALID_LOG_LEVELS:
        raise ValueError(f"log_level must be one of {VALID_LOG_LEVELS}")

    def decorate(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(self, *args, **kwargs) -> Dict[str, Any]:
            try:
                return fn(self, *args, **kwargs)
            except Exception as e:
                module_name = getattr(self, "MODULE_NAME",
                                       self.__class__.__name__)
                getattr(log, log_level)(
                    "module %s raised %s: %s",
                    module_name, type(e).__name__, e)
                # In debug-friendly mode, attach a short traceback. We
                # never include the full trace in the returned dict —
                # that goes to the log only.
                log.debug("traceback for %s:\n%s",
                           module_name, traceback.format_exc())
                if fallback == "raise":
                    raise
                base: Dict[str, Any] = {
                    "module":   module_name,
                    "findings": [],
                    "error":    f"{type(e).__name__}: {e}",
                }
                if fallback == "skip":
                    base["skipped"] = f"module raised: {type(e).__name__}"
                return base
        # Mark wrapped methods so tests can introspect.
        wrapper.__module_safe__ = {"fallback": fallback,
                                     "log_level": log_level}  # type: ignore[attr-defined]
        return wrapper
    return decorate
