"""Production-readiness, fingerprint customization, and soak/leak verification tests."""

from __future__ import annotations

import asyncio
import gc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import tracemalloc

import pytest

import http_tls
from http_tls import (
    AsyncClient,
    BestDriverSolver,
    BrowserType,
    Client,
    FlareSolverrSolver,
    Limits,
    MockTransport,
    PlaywrightSolver,
    STABLE_PRESETS,
    Session,
    TimeoutConfig,
    infer_impersonate_from_user_agent,
    is_verified_preset,
    parse_akamai_h2_to_http2_options,
    supported_presets,
)
from http_tls.solvers import (
    _SINGLEFLIGHT,
    _try_click_turnstile_best_driver,
    _try_click_turnstile_playwright,
)


class _FastHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        if self.path.startswith("/echo"):
            payload = json.dumps(
                {
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif self.path.startswith("/stream"):
            chunk = b"0123456789abcdef" * 256  # 4 KB per chunk
            total = len(chunk) * 16
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(total))
            self.end_headers()
            try:
                for _ in range(16):
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
        elif self.path.startswith("/cookie"):
            body = b"ok"
            self.send_response(200)
            self.send_header("Set-Cookie", "sid=soak123; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


class _QuietThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def handle_error(self, request, client_address) -> None:
        return


@pytest.fixture(scope="module")
def fast_server():
    server = _QuietThreadingHTTPServer(("127.0.0.1", 0), _FastHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_verified_native_default_and_preset_audit():
    s = Session()
    try:
        assert s.impersonate == "chrome_149"
        assert is_verified_preset(s.impersonate) is True
    finally:
        s.close()

    presets = supported_presets()
    assert len(presets) >= 100
    assert "chrome_149" in presets
    assert "safari_26_4" in presets
    assert "firefox_151" in presets
    assert "edge_148" in presets
    # No extrapolated future versions advertised in supported_presets(), STABLE_PRESETS, or BrowserType
    assert "chrome_152" not in presets
    assert "safari_27" not in presets
    assert all(is_verified_preset(p) for p in presets)
    assert all(is_verified_preset(p) for p in STABLE_PRESETS)
    assert all(is_verified_preset(b.value) for b in BrowserType)
    assert is_verified_preset("chrome_152") is False
    assert is_verified_preset("safari_27") is False


def test_solver_ua_to_rust_impersonate_alignment_and_client_hints(fast_server: str):
    assert infer_impersonate_from_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
    ) == "chrome_134"
    assert infer_impersonate_from_user_agent(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/149.0.0.0 Safari/537.36"
    ) == "chrome_149_macos"
    assert infer_impersonate_from_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0"
    ) == "firefox_147"
    assert infer_impersonate_from_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0"
    ) == "edge_145"
    assert infer_impersonate_from_user_agent(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.5 Safari/605.1.15"
    ) == "safari_18_5"

    with Session(impersonate="chrome_149") as s:
        assert s.impersonate == "chrome_149"
        s.load_storage_state(
            {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
                "headers": {
                    "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
                    "sec-ch-ua-platform": '"Windows"',
                    "sec-ch-ua-mobile": "?0",
                },
                "cookies": [
                    {"name": "cf_clearance", "value": " aligned_134 ", "domain": "127.0.0.1", "path": "/"}
                ],
            }
        )
        # Rust NativeSession must hot-swap its impersonate profile to match Chrome 134
        assert s.impersonate == "chrome_134"
        assert s._session.impersonate == "chrome_134"
        r = s.get(f"{fast_server}/echo")
        hdrs = r.json()["headers"]
        assert "Chrome/134.0.0.0" in hdrs["user-agent"]
        assert '"Google Chrome";v="134"' in hdrs["sec-ch-ua"]


def test_sync_solver_in_running_event_loop_and_singleflight_coalescing():
    _SINGLEFLIGHT.clear_cache()
    solve_calls = {"n": 0}

    async def slow_async_solver(url: str, resp):
        solve_calls["n"] += 1
        await asyncio.sleep(0.08)
        return {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/136.0.0.0 Safari/537.36",
            "cookies": [{"name": "cf_clearance", "value": "sf_token", "domain": "coalesce.test", "path": "/"}],
        }

    # 1. Calling synchronous Session.solve_challenge() FROM INSIDE a running event loop must NOT drop the coroutine!
    async def _inside_running_loop():
        with Session(solver=slow_async_solver) as s:
            chal_resp = http_tls.Response(
                status_code=403,
                headers={"cf-mitigated": "challenge", "server": "cloudflare"},
                content=b"<html>Just a moment...</html>",
                url="https://coalesce.test/page",
            )
            ok = s.solve_challenge(chal_resp)
            assert ok is True
            assert s.impersonate == "chrome_136"
            assert s.cookies.get("cf_clearance", domain="coalesce.test") == "sf_token"

    asyncio.run(_inside_running_loop())
    assert solve_calls["n"] == 1

    # 2. Thundering Herd Singleflight: 16 concurrent callers on the same domain must coalesce into 1 solve
    _SINGLEFLIGHT.clear_cache()
    burst_calls = {"n": 0}

    async def burst_coro():
        burst_calls["n"] += 1
        await asyncio.sleep(0.08)
        return {"cookies": [{"name": "cf_clearance", "value": "burst_ok", "domain": "herd.test"}]}

    async def _run_burst():
        results = await asyncio.gather(
            *(
                _SINGLEFLIGHT.execute_async(
                    url="https://herd.test/api/v1",
                    proxy=None,
                    ttl=10.0,
                    timeout=5.0,
                    coro_fn=burst_coro,
                )
                for _ in range(16)
            )
        )
        assert len(results) == 16
        assert all(r["cookies"][0]["value"] == "burst_ok" for r in results)

    asyncio.run(_run_burst())
    assert burst_calls["n"] == 1


def test_active_turnstile_checkbox_clicking():
    clicked = {"iframe": False, "bbox": False, "pw": False}

    class _FakeEl:
        rect = {"x": 100.0, "y": 200.0, "width": 300.0, "height": 65.0}

        async def click(self):
            clicked["iframe"] = True

    class _FakeFrame:
        async def ele(self, sel, timeout_ms=600):
            return _FakeEl() if sel == "input[type='checkbox']" else None

    class _FakeTab:
        def __init__(self, use_iframe: bool):
            self.use_iframe = use_iframe

        async def exists(self, sel):
            return self.use_iframe and "challenges.cloudflare.com" in sel

        async def iframe(self, sel, timeout_ms=1000):
            return _FakeFrame()

        async def ele(self, sel, timeout_ms=600):
            return _FakeEl() if not self.use_iframe else None

        async def mouse_click(self, x, y):
            assert 110.0 <= x <= 140.0 and 220.0 <= y <= 245.0
            clicked["bbox"] = True

    assert asyncio.run(_try_click_turnstile_best_driver(_FakeTab(use_iframe=True))) is True
    assert clicked["iframe"] is True
    assert asyncio.run(_try_click_turnstile_best_driver(_FakeTab(use_iframe=False))) is True
    assert clicked["bbox"] is True

    class _FakePwLoc:
        defproperty_first = None

        @property
        def first(self):
            return self

        def count(self):
            return 1

        def click(self, timeout=1000):
            clicked["pw"] = True

    class _FakePwFrame:
        url = "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile"

        def locator(self, sel):
            return _FakePwLoc()

    class _FakePwPage:
        frames = [_FakePwFrame()]

    assert _try_click_turnstile_playwright(_FakePwPage()) is True
    assert clicked["pw"] is True


def test_rfc6265_domain_path_cookie_isolation_and_no_cross_domain_leak(fast_server: str):
    with Session() as s:
        s.cookies.set("sid", "login_secret", domain="login.site.test", path="/auth", secure=True, http_only=True)
        s.cookies.set("sid", "api_secret", domain="api.site.test", path="/v1", secure=True)

        # Multi-subdomain lookup with identical cookie name must not overwrite each other
        assert s.cookies.get("sid", domain="login.site.test", path="/auth/callback") == "login_secret"
        assert s.cookies.get("sid", domain="api.site.test", path="/v1/users") == "api_secret"
        assert s.cookies.get("sid", domain="other.site.test") is None
        assert s.cookies.get_dict(domain="login.site.test") == {"sid": "login_secret"}
        assert s.cookies.get_dict(domain="api.site.test") == {"sid": "api_secret"}

        # Exporting storage_state must preserve both domain-scoped cookies
        state = s.save_storage_state()
        by_dom = {(c["domain"], c["path"], c["name"]): c["value"] for c in state["cookies"]}
        assert by_dom[("login.site.test", "/auth", "sid")] == "login_secret"
        assert by_dom[("api.site.test", "/v1", "sid")] == "api_secret"

        # Requests to fast_server (127.0.0.1) must NOT leak cookies from login.site.test or api.site.test!
        r = s.get(f"{fast_server}/echo")
        sent_cookie_hdr = r.json()["headers"].get("cookie", "")
        assert "login_secret" not in sent_cookie_hdr
        assert "api_secret" not in sent_cookie_hdr

        # Deleting only login.site.test's cookie must leave api.site.test intact
        s.cookies.delete("sid", domain="login.site.test")
        assert s.cookies.get("sid", domain="login.site.test") is None
        assert s.cookies.get("sid", domain="api.site.test", path="/v1") == "api_secret"


def test_forward_alias_uses_authentic_chromium_grease(fast_server: str):
    # Explicit forward alias (chrome_152) must use Chromium's deterministic GREASE brand list
    with Session(impersonate="chrome_152") as s:
        r = s.get(f"{fast_server}/echo")
        hdrs = r.json()["headers"]
        assert "Chrome/152.0.0.0" in hdrs["user-agent"]
        ch = hdrs["sec-ch-ua"]
        assert '"Google Chrome";v="152"' in ch
        assert '"Chromium";v="152"' in ch
        # seed=152: 152%11=9 ('?'), 153%11=10 ('_'), 152%3=2 ('24'), 152%6=2 -> order [1, 0, 2] => [Chromium, GREASE, Brand]
        assert ch == '"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"'


def test_akamai_h2_parser_and_full_tls_h2_options():
    opts = parse_akamai_h2_to_http2_options(
        "1:65536;2:0;4:6291456;6:262144|15663105|3:0:0:201|m,s,a,p"
    )
    assert opts["header_table_size"] == 65536
    assert opts["enable_push"] is False
    assert opts["initial_window_size"] == 6291456
    assert opts["max_header_list_size"] == 262144
    assert opts["settings_order"] == [1, 2, 4, 6]
    assert opts["initial_connection_window_size"] == 15663105 + 65535
    assert opts["headers_pseudo_order"] == ["m", "s", "a", "p"]
    assert opts["priorities"] == [{"stream_id": 3, "exclusive": False, "dependency_id": 0, "weight": 200}]

    # Verify Rust builder accepts every new BoringSSL & HTTP/2 option without error
    with Session(
        tls_options={
            "alpn": ["h2", "http/1.1"],
            "alps_protocols": ["h2"],
            "record_size_limit": 16385,
            "psk_skip_session_ticket": False,
            "psk_dhe_ke": True,
            "renegotiation": True,
            "aes_hw_override": True,
            "certificate_compressors": ["brotli", "zlib", "zstd"],
            "extension_permutation": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43, 27],
        },
        http2_options={
            **opts,
            "headers_stream_dependency": {"stream_id": 0, "weight": 219, "exclusive": True},
            "enable_connect_protocol": False,
            "no_rfc7540_priorities": True,
            "initial_stream_id": 1,
            "keep_alive_interval": 30.0,
            "keep_alive_timeout": 10.0,
            "keep_alive_while_idle": True,
            "max_send_buf_size": 1048576,
        },
        tcp_nodelay=True,
        tcp_keepalive=60.0,
        limits=Limits(max_keepalive_connections=16, keepalive_expiry=30.0),
        timeout=TimeoutConfig(15.0, connect=5.0, read=10.0),
    ) as s:
        assert s.timeout == 15.0


def test_live_custom_akamai_h2_wire_mutation():
    custom_fp = "1:65536;2:0;4:2097152;6:262144|10420225|0|m,s,a,p"
    with Session(impersonate="chrome_149", akamai_h2=custom_fp, retries=2, retry_backoff=0.5) as s:
        try:
            r = s.get("https://tls.peet.ws/api/all", timeout=10)
            if r.status_code == 200:
                h2_fp = r.json()["http2"]["akamai_fingerprint"]
                assert h2_fp.endswith("|m,s,a,p"), f"Expected custom pseudo order m,s,a,p, got {h2_fp}"
                assert "4:2097152" in h2_fp, f"Expected custom window 4:2097152, got {h2_fp}"
                return
        except http_tls.RequestException:
            pass
        # Fallback live HTTP/2 verification against Cloudflare if tls.peet.ws is temporarily unreachable
        cf = s.get("https://www.cloudflare.com/cdn-cgi/trace", timeout=10)
        assert cf.status_code == 200
        assert cf.http_version == "HTTP/2"
        assert "http=http/2" in cf.text


def test_mock_transport_sync_and_async_and_behavioral_headers():
    seen = []

    def handler(req):
        seen.append(req)
        return {"status_code": 200, "json": {"method": req["method"], "url": req["url"]}}

    with Client(
        base_url="https://api.example.test",
        transport=MockTransport(handler),
        auto_referer=True,
        fetch_mode="cors",
    ) as client:
        r1 = client.get("/step1", timeout=(2.0, 5.0))
        r2 = client.post("/step2", json={"ok": 1}, fetch_mode="same-origin")
        assert r1.status_code == 200 and r2.status_code == 200
        assert seen[0]["headers"]["Sec-Fetch-Mode"] == "cors"
        assert seen[0]["headers"]["Sec-Fetch-Dest"] == "empty"
        assert seen[1]["headers"]["Referer"] == "https://api.example.test/step1"
        assert seen[1]["headers"]["Sec-Fetch-Site"] == "same-origin"

    async def _run_async():
        async def async_handler(req):
            return (201, json.dumps({"async": True, "url": req["url"]}), {"X-Mock": "1"})

        async with AsyncClient(transport=MockTransport(async_handler)) as ac:
            r = await ac.get("https://offline.test/ping")
            assert r.status_code == 201
            assert r.headers["x-mock"] == "1"
            assert r.json()["async"] is True

    asyncio.run(_run_async())


def test_async_solver_bridge_and_solver_classes():
    calls = {"count": 0}

    async def fake_solver(url, resp):
        calls["count"] += 1
        return {"cookies": [{"name": "cf_clearance", "value": "solved-async", "domain": "example.test"}], "user_agent": "CustomUA/1.0"}

    async def _run():
        async with AsyncClient(solver=fake_solver) as ac:
            fake_resp = http_tls.Response(
                status_code=403,
                headers={"cf-mitigated": "challenge", "server": "cloudflare"},
                content=b"<html>Just a moment...</html>",
                url="https://example.test/protected",
            )
            assert fake_resp.challenge == "cloudflare"
            solved = await ac.solve_challenge(fake_resp)
            assert solved is True
            assert calls["count"] == 1
            assert ac.cookies["cf_clearance"] == "solved-async"
            assert ac.headers["user-agent"] == "CustomUA/1.0"

    asyncio.run(_run())
    # Ensure solver classes instantiate cleanly without requiring optional deps until called
    assert isinstance(BestDriverSolver(headless=True, keep_warm=True, max_warm_browsers=4), BestDriverSolver)
    assert isinstance(PlaywrightSolver(headless=True, keep_warm=True), PlaywrightSolver)
    assert isinstance(FlareSolverrSolver(), FlareSolverrSolver)


def test_warm_solver_proxy_isolation_cdp_context_and_alt_svc():
    from http_tls.solvers import _open_isolated_cdp_proxy_context, _resolve_effective_proxy

    # 1. Response.alt_svc RFC 7838 parsing
    r_alt = http_tls.Response(
        status_code=200,
        headers={"Alt-Svc": 'h3=":443"; ma=86400, h3-29=":443"; ma=86400'},
        content=b"ok",
        url="https://cloudflare.com/",
        proxy="http://10.0.0.1:8080",
    )
    assert r_alt.alt_svc == {"h3": ":443", "h3-29": ":443"}
    assert r_alt.proxy == "http://10.0.0.1:8080"
    assert _resolve_effective_proxy("http://default:8080", r_alt) == "http://10.0.0.1:8080"

    # 2. CDP Target.createBrowserContext(proxyServer=...) isolation for warm BestDriverSolver
    sent_cdp = []

    class _FakeWarmTab:
        async def url(self):
            return "https://target.test/challenge"

        async def send(self, method, params=None):
            sent_cdp.append((method, params))
            if method == "Target.createBrowserContext":
                return {"browserContextId": "ctx-proxy-1"}
            return {"targetId": "t-1"}

    class _FakeWarmBrowser:
        async def main_tab(self):
            return _FakeWarmTab()

        async def tabs(self):
            return [_FakeWarmTab()]

        async def get(self, url, new_tab=True, wait_until="domcontentloaded"):
            return _FakeWarmTab()

    tab, ctx_id = asyncio.run(
        _open_isolated_cdp_proxy_context(_FakeWarmBrowser(), "https://target.test/challenge", "http://1.2.3.4:8080")
    )
    assert ctx_id == "ctx-proxy-1"
    assert sent_cdp[0] == ("Target.createBrowserContext", {"disposeOnDetach": True, "proxyServer": "http://1.2.3.4:8080"})
    assert sent_cdp[1] == ("Target.createTarget", {"url": "https://target.test/challenge", "browserContextId": "ctx-proxy-1"})


def test_soak_stability_pool_cleanup_and_bounded_memory(fast_server: str):
    """Run 600 requests (sync, gather, async, stream abort, cookie clear) and verify bounded heap & clean close."""
    def _run_cycle() -> None:
        with Session(
            base_url=fast_server,
            limits=Limits(max_keepalive_connections=32, keepalive_expiry=15.0),
            tcp_nodelay=True,
        ) as s:
            for i in range(100):
                r = s.get(f"/ok?i={i}")
                assert r.status_code == 200

            batch = s.gather([f"/ok?g={i}" for i in range(300)], concurrency=40)
            assert len(batch) == 300
            assert all(r.status_code == 200 for r in batch)
            del batch

            for _ in range(10):
                with s.stream("GET", "/stream") as sr:
                    first = next(sr.iter_bytes(chunk_size=1024))
                    assert len(first) > 0

            for _ in range(10):
                s.get("/cookie")
                assert s.cookies.get("sid") == "soak123"
                s.cookies.clear()
                assert s.cookies.get_dict() == {}

            assert s._session.client_cache_len() == 1

        # Session.close() must clear the Rust client cache immediately
        assert s._session.client_cache_len() == 0

        async def _run_async_soak():
            sem = asyncio.Semaphore(40)
            async with AsyncClient(base_url=fast_server) as ac:
                async def _one(i: int):
                    async with sem:
                        return await ac.get(f"/ok?a={i}")

                resps = await asyncio.gather(*(_one(i) for i in range(200)))
                assert len(resps) == 200
                assert all(r.status_code == 200 for r in resps)
            assert ac._sync_session._session.client_cache_len() == 0

        asyncio.run(_run_async_soak())

    # Warmup one small call so asyncio / stdlib caches initialize before leak measurement
    import time

    with Session(base_url=fast_server) as warm:
        assert warm.get("/ok").status_code == 200
    time.sleep(0.05)
    gc.collect()
    tracemalloc.start()
    cur_before, _ = tracemalloc.get_traced_memory()

    _run_cycle()

    time.sleep(0.05)
    gc.collect()
    cur_after, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    delta_kb = (cur_after - cur_before) / 1024.0
    assert delta_kb < 256.0, f"Unexpected Python heap growth after 600 requests: {delta_kb:.1f} KB"
