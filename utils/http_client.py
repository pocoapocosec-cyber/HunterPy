"""Shared HTTP request helper.

Every module that fetches HTTP should go through `http_get`. This guarantees:
  * realistic browser User-Agent
  * 10-second connect/read timeout
  * redirect-following with a hard cap of 5
  * no exceptions ever raised — failures return None and are logged

The function tries `requests` first (richer response object + cookie jar +
auto-decompression) and falls back to `urllib` so the module works even if
`requests` isn't installed.
"""
from __future__ import annotations

import logging
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple


log = logging.getLogger("hunterpy.http")


DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/120.0.0.0 Safari/537.36 HunterPy/2.0")
DEFAULT_TIMEOUT = 10
MAX_REDIRECTS  = 5


try:
    import requests as _requests
    _HAVE_REQUESTS = True
except ImportError:                          # pragma: no cover
    _requests = None
    _HAVE_REQUESTS = False


class HTTPResponse:
    """Uniform response wrapper (mimics the bits of requests.Response we use)."""

    __slots__ = ("status_code", "url", "headers", "text",
                 "cookies", "raw_set_cookie")

    def __init__(self, status_code: int, url: str,
                 headers: Dict[str, str], text: str,
                 cookies: Optional[Dict[str, str]] = None,
                 raw_set_cookie: Optional[List[str]] = None):
        self.status_code     = status_code
        self.url             = url
        self.headers         = headers
        self.text            = text
        self.cookies         = cookies or {}
        self.raw_set_cookie  = raw_set_cookie or []


# --------------------------------------------------------------------------
def http_get(url: str,
             *,
             headers: Optional[Dict[str, str]] = None,
             cookies: Optional[str] = None,
             timeout: int = DEFAULT_TIMEOUT,
             user_agent: str = DEFAULT_UA,
             allow_redirects: bool = True,
             max_redirects: int = MAX_REDIRECTS,
             body_limit: int = 500_000) -> Optional[HTTPResponse]:
    """Fetch a URL safely. Returns HTTPResponse or None on any failure."""
    merged: Dict[str, str] = {"User-Agent": user_agent,
                              "Accept": "*/*",
                              "Accept-Language": "en-US,en;q=0.9"}
    if headers:
        merged.update(headers)
    if cookies:
        merged["Cookie"] = cookies

    if _HAVE_REQUESTS:
        return _get_requests(url, merged, timeout, allow_redirects,
                             max_redirects, body_limit)
    return _get_urllib(url, merged, timeout, allow_redirects,
                       max_redirects, body_limit)


# --------------------------------------------------------------------------
def _get_requests(url, headers, timeout, allow_redirects, max_redirects,
                  body_limit) -> Optional[HTTPResponse]:
    try:
        session = _requests.Session()
        session.max_redirects = max_redirects
        session.headers.update(headers)
        r = session.get(url, timeout=timeout, allow_redirects=allow_redirects)
        text = r.text[:body_limit] if r.text else ""
        return HTTPResponse(
            status_code=r.status_code,
            url=r.url,
            headers={k: v for k, v in r.headers.items()},
            text=text,
            cookies={c.name: c.value for c in r.cookies},
            raw_set_cookie=r.raw.headers.getlist("Set-Cookie")
                if hasattr(r.raw, "headers") else [],
        )
    except _requests.exceptions.Timeout:
        log.warning("[http] timeout %s", url)
    except _requests.exceptions.TooManyRedirects:
        log.warning("[http] too many redirects %s", url)
    except _requests.exceptions.SSLError as e:
        log.warning("[http] ssl error %s: %s", url, e)
    except _requests.exceptions.ConnectionError as e:
        log.warning("[http] connection error %s: %s", url, e)
    except _requests.RequestException as e:
        log.warning("[http] request error %s: %s", url, e)
    except Exception as e:
        log.warning("[http] unexpected error %s: %s", url, e)
    return None


def _get_urllib(url, headers, timeout, allow_redirects, max_redirects,
                body_limit) -> Optional[HTTPResponse]:
    class _CappedRedirect(urllib.request.HTTPRedirectHandler):
        max_repeats = max_redirects
        max_redirections = max_redirects
    opener = urllib.request.build_opener(_CappedRedirect()) if allow_redirects \
             else urllib.request.build_opener()
    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(body_limit).decode("utf-8", errors="replace")
            hdrs = {k: v for k, v in r.headers.items()}
            return HTTPResponse(
                status_code=r.status,
                url=r.url,
                headers=hdrs,
                text=body,
                raw_set_cookie=r.headers.get_all("Set-Cookie") or [],
            )
    except urllib.error.HTTPError as e:
        try:
            body = e.read(body_limit).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        hdrs = {k: v for k, v in (e.headers or {}).items()}
        return HTTPResponse(
            status_code=e.code, url=url, headers=hdrs, text=body,
            raw_set_cookie=(e.headers.get_all("Set-Cookie") if e.headers else []) or [],
        )
    except urllib.error.URLError as e:
        log.warning("[http] url error %s: %s", url, e)
    except TimeoutError:
        log.warning("[http] timeout %s", url)
    except Exception as e:
        log.warning("[http] unexpected error %s: %s", url, e)
    return None


# --------------------------------------------------------------------------
def head_status(url: str, **kw) -> Optional[int]:
    """Return the HTTP status code for `url`, using HEAD when possible
    and falling back to GET when the server returns 405 Method Not
    Allowed.

    The previous implementation called `http_get(url, body_limit=0)`,
    which technically transferred the full body and then sliced it to
    zero. That worked but was bandwidth-wasteful and contradicted the
    function's name.
    """
    # Prefer real HEAD via the helper. We fall back to GET in two cases:
    #   1. requests/urllib aren't HEAD-friendly here, OR
    #   2. the server returns 405 (HEAD not allowed)
    headers = kw.pop("headers", None) or {}
    timeout = kw.pop("timeout", DEFAULT_TIMEOUT)
    user_agent = kw.pop("user_agent", DEFAULT_UA)
    merged = {"User-Agent": user_agent, "Accept": "*/*"}
    merged.update(headers)

    # Stdlib HEAD path is identical across requests/urllib, so just
    # use urllib directly — no need for the requests/urllib branching.
    req = urllib.request.Request(url, method="HEAD", headers=merged)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        if e.code == 405:
            # HEAD not allowed → fall back to GET (with body discarded)
            r = http_get(url, headers=headers, timeout=timeout,
                         user_agent=user_agent, body_limit=0, **kw)
            return r.status_code if r else None
        return e.code
    except (urllib.error.URLError, TimeoutError, OSError):
        return None
    except Exception:
        return None


# --------------------------------------------------------------------------
def http_get_with_settings(settings, url: str, **kw) -> Optional[HTTPResponse]:
    """``http_get`` wrapper that respects the Settings UA rotation strategy.

    Modules that want per-request rotation should call this instead of
    plain ``http_get(url, user_agent=settings.user_agent, ...)``. Callers
    that need a deterministic UA (e.g. WAF baseline analyzer that wants
    to compare two responses with the same UA) can keep using
    ``http_get`` directly with an explicit ``user_agent=...``.
    """
    selector = getattr(settings, "ua_selector", None)
    if selector is not None and selector.strategy != "static":
        ua = selector.next()
    else:
        ua = getattr(settings, "user_agent", None) or DEFAULT_UA
    kw.pop("user_agent", None)        # callers shouldn't double-specify
    return http_get(url, user_agent=ua, **kw)
