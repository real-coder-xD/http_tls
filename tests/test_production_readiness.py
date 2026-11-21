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
    Client,
    FlareSolverrSolver,
    Limits,
    MockTransport,
    PlaywrightSolver,
    Session,
    TimeoutConfig,
    is_verified_preset,
    parse_akamai_h2_to_http2_options,
    supported_presets,
)


class _FastHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
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
    # No extrapolated future versions advertised in supported_presets()
    assert "chrome_152" not in presets
    assert "safari_27" not in presets
    assert all(is_verified_preset(p) for p in presets)
    assert is_verified_preset("chrome_152") is False
    assert is_verified_preset("safari_27") is False


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
    with Session(impersonate="chrome_149", akamai_h2=custom_fp) as s:
        r = s.get("https://tls.peet.ws/api/all", timeout=20)
        assert r.status_code == 200
        h2_fp = r.json()["http2"]["akamai_fingerprint"]
        assert h2_fp.endswith("|m,s,a,p"), f"Expected custom pseudo order m,s,a,p, got {h2_fp}"
        assert "4:2097152" in h2_fp, f"Expected custom window 4:2097152, got {h2_fp}"


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
    assert isinstance(BestDriverSolver(headless=True), BestDriverSolver)
    assert isinstance(PlaywrightSolver(headless=True), PlaywrightSolver)
    assert isinstance(FlareSolverrSolver(), FlareSolverrSolver)


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
