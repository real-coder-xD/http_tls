"""Optional browser & external challenge solver bridges for http_tls.

HTTP clients do not bundle a V8/JavaScript engine. When a target returns a
JavaScript proof-of-work or Turnstile interstitial (`resp.challenge is not None`),
attach one of these solvers to `Session(solver=..., retries=1, retry_on_challenge=True)`
to obtain clearance cookies + User-Agent and resume high-speed Rust BoringSSL requests.
"""

from __future__ import annotations

import asyncio
import json as _json
import time as _time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse


DEFAULT_CLEARANCE_COOKIES: Tuple[str, ...] = (
    "cf_clearance",
    "__cf_bm",
    "__ddg1_",
    "__ddg2_",
    "datadome",
    "_px3",
    "_pxhd",
    "reese84",
    "incap_ses_",
    "visid_incap_",
    "sucuri_cloudproxy_uuid",
)

_CHALLENGE_TITLE_MARKERS = (
    "just a moment",
    "attention required",
    "ddos-guard",
    "checking your browser",
    "verify you are human",
    "access denied",
)


def _has_clearance(cookies: Sequence[Any], names: Iterable[str]) -> bool:
    prefixes = tuple(n.lower() for n in names)
    for c in cookies:
        cname = str(c.get("name", "")).lower()
        if any(cname == p or cname.startswith(p) for p in prefixes):
            return True
    return False


class BestDriverSolver:
    """Challenge solver bridge powered by `best-driver` (stealth Rust CDP Chromium).

    Install `best-driver` separately (`pip install best-driver`) and pass an instance to
    `http_tls.Session(solver=BestDriverSolver(), retries=1, retry_on_challenge=True)`.
    Works seamlessly with both `Session` (sync) and `AsyncSession` (async).
    """

    def __init__(
        self,
        headless: bool = True,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        wait_cookies: Sequence[str] = DEFAULT_CLEARANCE_COOKIES,
        browser_path: Optional[str] = None,
        extra_args: Optional[Sequence[str]] = None,
    ) -> None:
        self.headless = headless
        self.timeout = float(timeout)
        self.proxy = proxy
        self.wait_cookies = tuple(wait_cookies)
        self.browser_path = browser_path
        self.extra_args = list(extra_args) if extra_args else None

    async def asolve(self, url: str, resp: Any = None) -> Dict[str, Any]:
        """Asynchronously solve a JS/WAF challenge via `best-driver` and return clearance data."""
        try:
            import best_driver  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "BestDriverSolver requires `best-driver`: pip install best-driver"
            ) from exc

        deadline = _time.monotonic() + self.timeout
        async with await best_driver.start(
            headless=self.headless,
            proxy=self.proxy,
            browser_path=self.browser_path,
            extra_args=self.extra_args,
        ) as browser:
            tab = await browser.get(url, wait_until="domcontentloaded")
            cookies: Sequence[Any] = []
            while _time.monotonic() < deadline:
                cookies = await tab.get_cookies([url])
                title = (await tab.title() or "").strip().lower()
                if _has_clearance(cookies, self.wait_cookies) and not any(
                    m in title for m in _CHALLENGE_TITLE_MARKERS
                ):
                    break
                await tab.sleep(0.5)
            ua = await tab.evaluate("navigator.userAgent")
            cookies = await tab.get_cookies([url])
            return {"cookies": list(cookies), "user_agent": str(ua) if ua else None}
        raise RuntimeError("BestDriverSolver failed to initialize browser")

    def __call__(self, url: str, resp: Any = None) -> Any:
        try:
            asyncio.get_running_loop()
            return self.asolve(url, resp)
        except RuntimeError:
            return asyncio.run(self.asolve(url, resp))


class PlaywrightSolver:
    """Challenge solver bridge powered by Playwright / Camoufox."""

    def __init__(
        self,
        headless: bool = True,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        wait_cookies: Sequence[str] = DEFAULT_CLEARANCE_COOKIES,
        browser_type: str = "chromium",
    ) -> None:
        self.headless = headless
        self.timeout = float(timeout)
        self.proxy = proxy
        self.wait_cookies = tuple(wait_cookies)
        self.browser_type = browser_type

    def __call__(self, url: str, resp: Any = None) -> Dict[str, Any]:
        try:
            from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "PlaywrightSolver requires `playwright`: pip install playwright"
            ) from exc

        launch_kw: Dict[str, Any] = {"headless": self.headless}
        if self.proxy:
            parsed = urlparse(self.proxy)
            px: Dict[str, Any] = {"server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"}
            if parsed.username:
                px["username"] = parsed.username
            if parsed.password:
                px["password"] = parsed.password
            launch_kw["proxy"] = px

        deadline = _time.monotonic() + self.timeout
        with sync_playwright() as p:
            launcher = getattr(p, self.browser_type)
            browser = launcher.launch(**launch_kw)
            try:
                ctx = browser.new_context()
                page = ctx.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=int(self.timeout * 1000))
                cookies: Sequence[Any] = []
                while _time.monotonic() < deadline:
                    cookies = ctx.cookies([url])
                    title = (page.title() or "").strip().lower()
                    if _has_clearance(cookies, self.wait_cookies) and not any(
                        m in title for m in _CHALLENGE_TITLE_MARKERS
                    ):
                        break
                    page.wait_for_timeout(500)
                ua = page.evaluate("() => navigator.userAgent")
                cookies = ctx.cookies([url])
                return {"cookies": list(cookies), "user_agent": str(ua) if ua else None}
            finally:
                browser.close()


class FlareSolverrSolver:
    """Challenge solver bridge for a local or remote FlareSolverr `/v1` endpoint."""

    def __init__(
        self,
        endpoint: str = "http://localhost:8191/v1",
        max_timeout_ms: int = 60000,
        proxy: Optional[str] = None,
    ) -> None:
        self.endpoint = endpoint
        self.max_timeout_ms = int(max_timeout_ms)
        self.proxy = proxy

    def __call__(self, url: str, resp: Any = None) -> Dict[str, Any]:
        from http_tls.requests import Session

        payload: Dict[str, Any] = {
            "cmd": "request.get",
            "url": url,
            "maxTimeout": self.max_timeout_ms,
        }
        if self.proxy:
            payload["proxy"] = {"url": self.proxy}

        with Session(timeout=max(30.0, self.max_timeout_ms / 1000.0 + 5.0)) as helper:
            res = helper.post(self.endpoint, json=payload)
            data = _json.loads(res.text)
            sol = data.get("solution") or {}
            return {
                "cookies": sol.get("cookies", []),
                "user_agent": sol.get("userAgent"),
            }
