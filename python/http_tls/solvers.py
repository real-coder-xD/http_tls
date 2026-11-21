"""Browser & external challenge solver bridges for http_tls.

Features:
- Synchronous & asynchronous execution without dropped coroutines: when called
  from synchronous code inside an already-running event loop (FastAPI, Jupyter,
  async workers), dispatches onto a dedicated background event-loop thread.
- Per-domain Singleflight coalescing lock + TTL clearance cache: when N threads
  or tasks hit a 403 challenge on the same domain simultaneously, only 1 browser
  solve runs while the other N-1 waiters share the solved clearance state.
- Optional warm browser reuse (`keep_warm=True`) to avoid cold-starting Chromium.
- Active Cloudflare Turnstile & challenge checkbox clicking (piercing open/closed
  Shadow DOM and challenge iframes with humanized cursor movement).
- Full fingerprint synchronization: extracts `User-Agent`, `Sec-CH-UA*` Client
  Hints headers, and infers the matching `http_tls` Rust `impersonate` profile
  so TLS JA4, HTTP/2 frames, Client Hints, and `User-Agent` stay 1:1 aligned.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import Future as _ConcurrentFuture
import json as _json
import re
import threading
import time as _time
from typing import Any, Callable, Coroutine, Dict, Iterable, List, Optional, Sequence, Tuple
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
    "security check",
)

_TURNSTILE_IFRAME_SELECTORS: Tuple[str, ...] = (
    "iframe[src*='challenges.cloudflare.com']",
    "iframe[src*='turnstile']",
    "iframe[title*='Cloudflare']",
    "iframe[title*=' security challenge']",
    "#turnstile-wrapper iframe",
    ".cf-turnstile iframe",
)

_TURNSTILE_CONTAINER_SELECTORS: Tuple[str, ...] = (
    "iframe[src*='challenges.cloudflare.com']",
    ".cf-turnstile",
    "#turnstile-wrapper",
    "#challenge-stage",
    "#cf-turnstile",
)

_CLIENT_HINTS_JS = """
(async () => {
    const ua = navigator.userAgent || "";
    const out = { user_agent: ua, headers: {} };
    try {
        const uad = navigator.userAgentData;
        if (uad && Array.isArray(uad.brands) && uad.brands.length) {
            out.headers["sec-ch-ua"] = uad.brands
                .map(b => `"${b.brand}";v="${b.version}"`)
                .join(", ");
            out.headers["sec-ch-ua-mobile"] = uad.mobile ? "?1" : "?0";
            if (uad.platform) {
                out.headers["sec-ch-ua-platform"] = `"${uad.platform}"`;
            }
            if (typeof uad.getHighEntropyValues === "function") {
                const hi = await uad.getHighEntropyValues([
                    "architecture",
                    "bitness",
                    "fullVersionList",
                    "model",
                    "platformVersion"
                ]);
                if (hi.architecture) out.headers["sec-ch-ua-arch"] = `"${hi.architecture}"`;
                if (hi.bitness) out.headers["sec-ch-ua-bitness"] = `"${hi.bitness}"`;
                if (hi.model !== undefined) out.headers["sec-ch-ua-model"] = `"${hi.model}"`;
                if (hi.platformVersion) out.headers["sec-ch-ua-platform-version"] = `"${hi.platformVersion}"`;
                if (Array.isArray(hi.fullVersionList) && hi.fullVersionList.length) {
                    out.headers["sec-ch-ua-full-version-list"] = hi.fullVersionList
                        .map(b => `"${b.brand}";v="${b.version}"`)
                        .join(", ");
                }
            }
        }
    } catch (_) {}
    return out;
})()
"""


def _has_clearance(cookies: Sequence[Any], names: Iterable[str]) -> bool:
    prefixes = tuple(n.lower() for n in names)
    for c in cookies:
        cname = str(c.get("name", "") if isinstance(c, dict) else "").lower()
        if any(cname == p or cname.startswith(p) for p in prefixes):
            return True
    return False


# ---------------------------------------------------------------------------
# Dedicated background event-loop thread (prevents dropped coroutines when
# synchronous code calls an async solver from inside FastAPI/Jupyter/workers)
# ---------------------------------------------------------------------------
class _BackgroundLoopRunner:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._loop is not None and self._loop.is_running():
                return self._loop
            ready = threading.Event()
            loop_holder: List[asyncio.AbstractEventLoop] = []

            def _worker() -> None:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop_holder.append(loop)
                ready.set()
                loop.run_forever()

            t = threading.Thread(target=_worker, name="http_tls_solver_loop", daemon=True)
            t.start()
            ready.wait(timeout=5.0)
            self._loop = loop_holder[0]
            self._thread = t
            return self._loop

    def run_sync(self, coro: Coroutine[Any, Any, Dict[str, Any]], timeout: Optional[float] = None) -> Dict[str, Any]:
        loop = self._ensure_loop()
        fut = asyncio.run_coroutine_threadsafe(coro, loop)
        return fut.result(timeout=timeout)


_BG_RUNNER = _BackgroundLoopRunner()


def run_coroutine_sync(coro: Coroutine[Any, Any, Dict[str, Any]], timeout: Optional[float] = None) -> Dict[str, Any]:
    """Run `coro` to completion and return its dict result even if the current thread has a running event loop."""
    try:
        asyncio.get_running_loop()
        has_running_loop = True
    except RuntimeError:
        has_running_loop = False

    if not has_running_loop:
        return asyncio.run(coro)
    return _BG_RUNNER.run_sync(coro, timeout=timeout)


# ---------------------------------------------------------------------------
# Per-Domain Singleflight Coalescing Coordinator + TTL Clearance Cache
# ---------------------------------------------------------------------------
class _SingleflightCoordinator:
    """Coalesces concurrent challenge solves for the same `(host, proxy)` into a single browser run."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._inflight: Dict[Tuple[str, str], _ConcurrentFuture[Dict[str, Any]]] = {}
        self._cache: Dict[Tuple[str, str], Tuple[float, Dict[str, Any]]] = {}

    @staticmethod
    def _key(url: str, proxy: Optional[str]) -> Tuple[str, str]:
        host = (urlparse(url).hostname or url).lower()
        return (host, proxy or "")

    def get_cached(self, url: str, proxy: Optional[str], ttl: float) -> Optional[Dict[str, Any]]:
        if ttl <= 0:
            return None
        key = self._key(url, proxy)
        with self._lock:
            entry = self._cache.get(key)
            if entry is not None:
                ts, state = entry
                if _time.monotonic() - ts <= ttl:
                    return dict(state)
                del self._cache[key]
        return None

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    def execute_sync(
        self,
        url: str,
        proxy: Optional[str],
        ttl: float,
        timeout: float,
        fn: Callable[[], Dict[str, Any]],
    ) -> Dict[str, Any]:
        cached = self.get_cached(url, proxy, ttl)
        if cached is not None:
            return cached

        key = self._key(url, proxy)
        with self._lock:
            cached = self.get_cached(url, proxy, ttl)
            if cached is not None:
                return cached
            existing = self._inflight.get(key)
            if existing is None:
                leader_fut: _ConcurrentFuture[Dict[str, Any]] = _ConcurrentFuture()
                self._inflight[key] = leader_fut
                is_leader = True
            else:
                leader_fut = existing
                is_leader = False

        if not is_leader:
            return dict(leader_fut.result(timeout=timeout + 15.0))

        try:
            result = fn()
            with self._lock:
                if ttl > 0 and result.get("cookies"):
                    self._cache[key] = (_time.monotonic(), dict(result))
                self._inflight.pop(key, None)
            leader_fut.set_result(result)
            return dict(result)
        except BaseException as exc:
            with self._lock:
                self._inflight.pop(key, None)
            leader_fut.set_exception(exc)
            raise

    async def execute_async(
        self,
        url: str,
        proxy: Optional[str],
        ttl: float,
        timeout: float,
        coro_fn: Callable[[], Coroutine[Any, Any, Dict[str, Any]]],
    ) -> Dict[str, Any]:
        cached = self.get_cached(url, proxy, ttl)
        if cached is not None:
            return cached

        key = self._key(url, proxy)
        with self._lock:
            cached = self.get_cached(url, proxy, ttl)
            if cached is not None:
                return cached
            existing = self._inflight.get(key)
            if existing is None:
                leader_fut: _ConcurrentFuture[Dict[str, Any]] = _ConcurrentFuture()
                self._inflight[key] = leader_fut
                is_leader = True
            else:
                leader_fut = existing
                is_leader = False

        if not is_leader:
            wrapped = asyncio.wrap_future(leader_fut)
            res = await asyncio.wait_for(wrapped, timeout=timeout + 15.0)
            return dict(res)

        try:
            result = await coro_fn()
            with self._lock:
                if ttl > 0 and result.get("cookies"):
                    self._cache[key] = (_time.monotonic(), dict(result))
                self._inflight.pop(key, None)
            leader_fut.set_result(result)
            return dict(result)
        except BaseException as exc:
            with self._lock:
                self._inflight.pop(key, None)
            leader_fut.set_exception(exc)
            raise


_SINGLEFLIGHT = _SingleflightCoordinator()


def infer_impersonate_from_user_agent(ua: str) -> Optional[str]:
    """Map a browser `User-Agent` string to the closest verified native `http_tls` preset.

    Ensures TLS JA3/JA4, HTTP/2 SETTINGS, and `Sec-CH-UA` headers match the browser
    that solved the challenge.
    """
    if not ua:
        return None
    low = ua.lower()
    is_mac = "macintosh" in low or "mac os x" in low
    is_android = "android" in low
    is_ipad = "ipad" in low
    is_ios = "iphone" in low or "ios" in low

    # 1. Microsoft Edge (Edg/, EdgA/, EdgiOS/)
    m_edge = re.search(r"edg(?:a|ios)?/(\d+)", low)
    if m_edge:
        ver = int(m_edge.group(1))
        supported_edge = (101, 122, 127, 131, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148)
        best = min(supported_edge, key=lambda x: (abs(x - min(ver, 148)), -x))
        return f"edge_{best}"

    # 2. Opera (OPR/)
    m_opr = re.search(r"opr/(\d+)", low)
    if m_opr:
        ver = int(m_opr.group(1))
        supported_opr = tuple(range(116, 132))
        best = min(supported_opr, key=lambda x: (abs(x - min(ver, 131)), -x))
        return f"opera_{best}"

    # 3. Firefox (Firefox/)
    m_ff = re.search(r"firefox/(\d+)", low)
    if m_ff:
        ver = int(m_ff.group(1))
        if is_android:
            return "firefox_android_135"
        supported_ff = (109, 117, 128, 133, 135, 136, 139, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151)
        best = min(supported_ff, key=lambda x: (abs(x - min(ver, 151)), -x))
        return f"firefox_{best}"

    # 4. Chrome / Chromium (Chrome/ or CriOS/)
    m_chr = re.search(r"(?:chrome|crios)/(\d+)", low)
    if m_chr:
        ver = int(m_chr.group(1))
        if is_android and ver <= 135:
            return "chrome_131_android"
        supported_chr = (
            100, 104, 107, 110, 114, 116, 119, 120, 123, 124, 126, 127, 128, 129, 130,
            131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145,
            146, 147, 148, 149,
        )
        best = min(supported_chr, key=lambda x: (abs(x - min(ver, 149)), -x))
        if is_mac and best == 149:
            return "chrome_149_macos"
        return f"chrome_{best}"

    # 5. Safari (Version/XX.Y ... Safari/)
    m_saf = re.search(r"version/(\d+)(?:\.(\d+))?", low)
    if m_saf and "safari/" in low:
        maj = int(m_saf.group(1))
        minor = int(m_saf.group(2) or 0)
        if is_ipad:
            return "safari_ipad_26_2" if (maj >= 26 and minor >= 2) else ("safari_ipad_26" if maj >= 26 else "safari_ipad_18")
        if is_ios:
            return "safari_ios_26_2" if (maj >= 26 and minor >= 2) else ("safari_ios_26" if maj >= 26 else "safari_ios_18_1_1")
        if maj >= 26:
            if minor >= 4:
                return "safari_26_4"
            if minor in (1, 2, 3):
                return f"safari_26_{minor}"
            return "safari_26"
        if maj == 18:
            return "safari_18_5" if minor >= 4 else ("safari_18_3" if minor == 3 else ("safari_18_2" if minor == 2 else "safari_18"))
        if maj == 17:
            return "safari_17_6"
        if maj == 16:
            return "safari_16_5"
        return "safari_15_5"

    return None


async def _try_click_turnstile_best_driver(tab: Any) -> bool:
    """Attempt to locate and click a Cloudflare Turnstile / interstitial checkbox in `best-driver`."""
    # 1. Try piercing the Turnstile iframe directly (works across open/closed Shadow DOM and OOPIFs)
    for sel in _TURNSTILE_IFRAME_SELECTORS:
        try:
            if await tab.exists(sel):
                frame = await tab.iframe(sel, timeout_ms=1000)
                for inner_sel in ("input[type='checkbox']", ".cb-lb", "#challenge-stage", "label", "body"):
                    el = await frame.ele(inner_sel, timeout_ms=600)
                    if el is not None:
                        await el.click()
                        return True
        except Exception:
            pass

    # 2. Fallback: click the left-side checkbox coordinates inside the Turnstile widget container rect
    for sel in _TURNSTILE_CONTAINER_SELECTORS:
        try:
            el = await tab.ele(sel, timeout_ms=600)
            if el is not None and isinstance(getattr(el, "rect", None), dict):
                rect = el.rect
                w = float(rect.get("width", 0.0))
                h = float(rect.get("height", 0.0))
                if w >= 40.0 and h >= 20.0:
                    cx = float(rect.get("x", 0.0)) + min(28.0, w * 0.25)
                    cy = float(rect.get("y", 0.0)) + h * 0.5
                    await tab.mouse_click(cx, cy)
                    return True
        except Exception:
            pass
    return False


def _try_click_turnstile_playwright(page: Any) -> bool:
    """Attempt to locate and click a Cloudflare Turnstile / interstitial checkbox in Playwright."""
    try:
        for frame in page.frames:
            furl = (frame.url or "").lower()
            if "challenges.cloudflare.com" in furl or "turnstile" in furl:
                for inner_sel in ("input[type='checkbox']", ".cb-lb", "label", "body"):
                    loc = frame.locator(inner_sel).first
                    if loc.count() > 0:
                        loc.click(timeout=1000)
                        return True
    except Exception:
        pass

    for sel in _TURNSTILE_CONTAINER_SELECTORS:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0:
                box = loc.bounding_box()
                if box and box["width"] >= 40 and box["height"] >= 20:
                    cx = box["x"] + min(28.0, box["width"] * 0.25)
                    cy = box["y"] + box["height"] * 0.5
                    page.mouse.move(cx, cy, steps=10)
                    page.mouse.click(cx, cy)
                    return True
        except Exception:
            pass
    return False


class BestDriverSolver:
    """Challenge solver bridge powered by `best-driver` (stealth Rust CDP Chromium).

    - Safe from both sync (`Session`) and async (`AsyncSession`) callers, even inside
      an already-running event loop (FastAPI, Jupyter, workers) — never drops a coroutine.
    - Uses per-domain Singleflight coalescing + TTL cache to prevent Thundering Herd.
    - Supports `keep_warm=True` to reuse a single persistent Chromium instance across challenges.
    - Actively clicks Cloudflare Turnstile checkboxes (piercing closed Shadow DOM & OOPIF).
    - Extracts `User-Agent`, `Sec-CH-UA*` Client Hints, and matching `impersonate` preset.
    """

    def __init__(
        self,
        headless: bool = True,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        wait_cookies: Sequence[str] = DEFAULT_CLEARANCE_COOKIES,
        browser_path: Optional[str] = None,
        extra_args: Optional[Sequence[str]] = None,
        keep_warm: bool = False,
        cache_ttl: float = 15.0,
        click_turnstile: bool = True,
    ) -> None:
        self.headless = headless
        self.timeout = float(timeout)
        self.proxy = proxy
        self.wait_cookies = tuple(wait_cookies)
        self.browser_path = browser_path
        self.extra_args = list(extra_args) if extra_args else None
        self.keep_warm = bool(keep_warm)
        self.cache_ttl = float(cache_ttl)
        self.click_turnstile = bool(click_turnstile)
        self._warm_browser: Any = None
        self._warm_lock: Optional[asyncio.Lock] = None

    async def _solve_with_tab(self, tab: Any, url: str) -> Dict[str, Any]:
        deadline = _time.monotonic() + self.timeout
        cookies: Sequence[Any] = []
        last_click = 0.0
        while _time.monotonic() < deadline:
            cookies = await tab.get_cookies([url])
            title = (await tab.title() or "").strip().lower()
            if _has_clearance(cookies, self.wait_cookies) and not any(
                m in title for m in _CHALLENGE_TITLE_MARKERS
            ):
                break
            now = _time.monotonic()
            if self.click_turnstile and (now - last_click) >= 1.5:
                last_click = now
                await _try_click_turnstile_best_driver(tab)
            await tab.sleep(0.5)

        ch_info = await tab.evaluate(_CLIENT_HINTS_JS)
        ua_str: Optional[str] = None
        ch_headers: Dict[str, str] = {}
        if isinstance(ch_info, dict):
            ua_val = ch_info.get("user_agent")
            if ua_val:
                ua_str = str(ua_val)
            raw_hdrs = ch_info.get("headers")
            if isinstance(raw_hdrs, dict):
                ch_headers = {str(k): str(v) for k, v in raw_hdrs.items() if v is not None}
        if not ua_str:
            ua_eval = await tab.evaluate("navigator.userAgent")
            ua_str = str(ua_eval) if ua_eval else None

        cookies = await tab.get_cookies([url])
        inferred = infer_impersonate_from_user_agent(ua_str or "")
        return {
            "cookies": list(cookies),
            "user_agent": ua_str,
            "headers": ch_headers,
            "impersonate": inferred,
        }

    async def _asolve_uncached(self, url: str) -> Dict[str, Any]:
        try:
            import best_driver  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "BestDriverSolver requires `best-driver`: pip install best-driver"
            ) from exc

        if self.keep_warm:
            if self._warm_lock is None:
                self._warm_lock = asyncio.Lock()
            async with self._warm_lock:
                if self._warm_browser is None or not await self._warm_browser.is_alive():
                    self._warm_browser = await best_driver.start(
                        headless=self.headless,
                        proxy=self.proxy,
                        browser_path=self.browser_path,
                        extra_args=self.extra_args,
                    )
                tab = await self._warm_browser.get(url, new_tab=True, wait_until="domcontentloaded")
                try:
                    return await self._solve_with_tab(tab, url)
                finally:
                    try:
                        await tab.close()
                    except Exception:
                        pass

        async with await best_driver.start(
            headless=self.headless,
            proxy=self.proxy,
            browser_path=self.browser_path,
            extra_args=self.extra_args,
        ) as browser:
            tab = await browser.get(url, wait_until="domcontentloaded")
            return await self._solve_with_tab(tab, url)
        raise RuntimeError("BestDriverSolver failed to initialize browser")

    async def asolve(self, url: str, resp: Any = None) -> Dict[str, Any]:
        """Asynchronously solve a JS/WAF challenge with per-domain Singleflight coalescing."""
        return await _SINGLEFLIGHT.execute_async(
            url=url,
            proxy=self.proxy,
            ttl=self.cache_ttl,
            timeout=self.timeout,
            coro_fn=lambda: self._asolve_uncached(url),
        )

    def __call__(self, url: str, resp: Any = None) -> Dict[str, Any]:
        """Synchronously solve a JS/WAF challenge, safe even inside a running asyncio event loop."""
        return run_coroutine_sync(self.asolve(url, resp), timeout=self.timeout + 15.0)

    async def aclose(self) -> None:
        """Close the warm browser instance if `keep_warm=True` was used."""
        if self._warm_browser is not None:
            try:
                await self._warm_browser.stop()
            finally:
                self._warm_browser = None

    def close(self) -> None:
        if self._warm_browser is not None:
            run_coroutine_sync(self._close_coro(), timeout=10.0)

    async def _close_coro(self) -> Dict[str, Any]:
        await self.aclose()
        return {}


class PlaywrightSolver:
    """Challenge solver bridge powered by Playwright / Camoufox with Singleflight, Turnstile clicking & Client Hints sync."""

    def __init__(
        self,
        headless: bool = True,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        wait_cookies: Sequence[str] = DEFAULT_CLEARANCE_COOKIES,
        browser_type: str = "chromium",
        cache_ttl: float = 15.0,
        click_turnstile: bool = True,
    ) -> None:
        self.headless = headless
        self.timeout = float(timeout)
        self.proxy = proxy
        self.wait_cookies = tuple(wait_cookies)
        self.browser_type = browser_type
        self.cache_ttl = float(cache_ttl)
        self.click_turnstile = bool(click_turnstile)

    def _solve_uncached(self, url: str) -> Dict[str, Any]:
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
                last_click = 0.0
                while _time.monotonic() < deadline:
                    cookies = ctx.cookies([url])
                    title = (page.title() or "").strip().lower()
                    if _has_clearance(cookies, self.wait_cookies) and not any(
                        m in title for m in _CHALLENGE_TITLE_MARKERS
                    ):
                        break
                    now = _time.monotonic()
                    if self.click_turnstile and (now - last_click) >= 1.5:
                        last_click = now
                        _try_click_turnstile_playwright(page)
                    page.wait_for_timeout(500)

                ch_info = page.evaluate(_CLIENT_HINTS_JS)
                ua_str: Optional[str] = None
                ch_headers: Dict[str, str] = {}
                if isinstance(ch_info, dict):
                    ua_val = ch_info.get("user_agent")
                    if ua_val:
                        ua_str = str(ua_val)
                    raw_hdrs = ch_info.get("headers")
                    if isinstance(raw_hdrs, dict):
                        ch_headers = {str(k): str(v) for k, v in raw_hdrs.items() if v is not None}
                if not ua_str:
                    ua_eval = page.evaluate("() => navigator.userAgent")
                    ua_str = str(ua_eval) if ua_eval else None

                cookies = ctx.cookies([url])
                return {
                    "cookies": list(cookies),
                    "user_agent": ua_str,
                    "headers": ch_headers,
                    "impersonate": infer_impersonate_from_user_agent(ua_str or ""),
                }
            finally:
                browser.close()

    def __call__(self, url: str, resp: Any = None) -> Dict[str, Any]:
        return _SINGLEFLIGHT.execute_sync(
            url=url,
            proxy=self.proxy,
            ttl=self.cache_ttl,
            timeout=self.timeout,
            fn=lambda: self._solve_uncached(url),
        )


class FlareSolverrSolver:
    """Challenge solver bridge for a local or remote FlareSolverr `/v1` endpoint with Singleflight & UA preset sync."""

    def __init__(
        self,
        endpoint: str = "http://localhost:8191/v1",
        max_timeout_ms: int = 60000,
        proxy: Optional[str] = None,
        cache_ttl: float = 15.0,
    ) -> None:
        self.endpoint = endpoint
        self.max_timeout_ms = int(max_timeout_ms)
        self.proxy = proxy
        self.cache_ttl = float(cache_ttl)

    def _solve_uncached(self, url: str) -> Dict[str, Any]:
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
            ua_str = sol.get("userAgent")
            return {
                "cookies": sol.get("cookies", []),
                "user_agent": ua_str,
                "impersonate": infer_impersonate_from_user_agent(str(ua_str or "")),
            }

    def __call__(self, url: str, resp: Any = None) -> Dict[str, Any]:
        return _SINGLEFLIGHT.execute_sync(
            url=url,
            proxy=self.proxy,
            ttl=self.cache_ttl,
            timeout=self.max_timeout_ms / 1000.0,
            fn=lambda: self._solve_uncached(url),
        )
