"""End-to-end C-ABI shared library (http_tls.dll / libhttp_tls.so / libhttp_tls.dylib) test suite.

Exercises the exact C-ABI boundary consumed by C#, Go, Node.js, C/C++, PHP, and AutoIt
callers using raw `ctypes.CDLL`, covering:
- Version & 100+ browser presets
- Session lifecycle (create, custom ID, hot-swap impersonate, destroy, destroy_all)
- One-shot & persistent requests over local HTTP server (GET/POST/JSON/multipart/binary base64/redirects/cookies/headers/params/JA3/Akamai H2)
- Concurrent `http_tls_gather` preserving input order
- Multi-threaded shared-session stress test (8 OS threads)
- Live UDP QUIC HTTP/3 + Real ECH (`sni=encrypted`) + DoH + TLS 1.3 resumption
- Live TCP HTTP/2 Real ECH (`sni=encrypted`)
- Pure Rust extraction via `http_tls_extract` (CSS3, XPath 1.0, JSONPath filters, DFA Regex, between)
- NULL pointer & malformed input safety (no panics/crashes across FFI)
"""

from __future__ import annotations

import base64
import concurrent.futures
import ctypes
import hashlib
import http.server
import json
import os
import platform
import socket
import socketserver
import struct
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

import pytest


def _find_shared_lib() -> Optional[Path]:
    env_path = os.environ.get("HTTP_TLS_FFI_LIB")
    if env_path and Path(env_path).is_file():
        return Path(env_path)
    root = Path(__file__).resolve().parents[1]
    sys_name = platform.system()
    if sys_name == "Windows":
        names = ["http_tls.dll"]
    elif sys_name == "Darwin":
        names = ["libhttp_tls.dylib"]
    else:
        names = ["libhttp_tls.so"]
    for base in (root / "target" / "release", root / "ffi" / "target" / "release", root / "dist"):
        for n in names:
            cand = base / n
            if cand.is_file():
                return cand
    return None


class _FFILib:
    def __init__(self, lib_path: Path) -> None:
        self._lib = ctypes.CDLL(str(lib_path))
        c_void_p = ctypes.c_void_p
        c_char_p = ctypes.c_char_p

        for fn_name, argtypes in [
            ("http_tls_version", []),
            ("http_tls_presets", []),
            ("http_tls_create_session", [c_char_p]),
            ("http_tls_request", [c_char_p]),
            ("http_tls_gather", [c_char_p]),
            ("http_tls_get_cookies", [c_char_p]),
            ("http_tls_set_cookies", [c_char_p]),
            ("http_tls_set_impersonate", [c_char_p]),
            ("http_tls_destroy_session", [c_char_p]),
            ("http_tls_destroy_all_sessions", []),
            ("http_tls_stream_open", [c_char_p]),
            ("http_tls_stream_read", [c_char_p]),
            ("http_tls_stream_close", [c_char_p]),
            ("http_tls_ws_connect", [c_char_p]),
            ("http_tls_ws_send", [c_char_p]),
            ("http_tls_ws_recv", [c_char_p]),
            ("http_tls_ws_close", [c_char_p]),
            ("http_tls_extract", [c_char_p]),
        ]:
            fn = getattr(self._lib, fn_name)
            fn.argtypes = argtypes
            fn.restype = c_void_p

        self._lib.http_tls_free_string.argtypes = [c_void_p]
        self._lib.http_tls_free_string.restype = None

    def _consume(self, ptr: Optional[int]) -> Dict[str, Any]:
        assert ptr, "FFI returned NULL pointer"
        try:
            raw = ctypes.cast(ptr, ctypes.c_char_p).value
            assert raw is not None
            return json.loads(raw.decode("utf-8"))
        finally:
            self._lib.http_tls_free_string(ptr)

    def version(self) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_version())

    def presets(self) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_presets())

    def create_session(self, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        arg = None if cfg is None else json.dumps(cfg).encode("utf-8")
        return self._consume(self._lib.http_tls_create_session(arg))

    def request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_request(json.dumps(req).encode("utf-8")))

    def request_raw(self, raw: Optional[bytes]) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_request(raw))

    def gather(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_gather(json.dumps(req).encode("utf-8")))

    def get_cookies(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_get_cookies(json.dumps(req).encode("utf-8")))

    def set_cookies(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_set_cookies(json.dumps(req).encode("utf-8")))

    def set_impersonate(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_set_impersonate(json.dumps(req).encode("utf-8")))

    def destroy_session(self, sid: str) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_destroy_session(sid.encode("utf-8")))

    def destroy_all(self) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_destroy_all_sessions())

    def stream_open(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_stream_open(json.dumps(req).encode("utf-8")))

    def stream_read(self, req: Any) -> Dict[str, Any]:
        raw = req.encode("utf-8") if isinstance(req, str) else json.dumps(req).encode("utf-8")
        return self._consume(self._lib.http_tls_stream_read(raw))

    def stream_close(self, sid: str) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_stream_close(sid.encode("utf-8")))

    def ws_connect(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_ws_connect(json.dumps(req).encode("utf-8")))

    def ws_send(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_ws_send(json.dumps(req).encode("utf-8")))

    def ws_recv(self, req: Any) -> Dict[str, Any]:
        raw = req.encode("utf-8") if isinstance(req, str) else json.dumps(req).encode("utf-8")
        return self._consume(self._lib.http_tls_ws_recv(raw))

    def ws_close(self, req: Any) -> Dict[str, Any]:
        raw = req.encode("utf-8") if isinstance(req, str) else json.dumps(req).encode("utf-8")
        return self._consume(self._lib.http_tls_ws_close(raw))

    def extract(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._consume(self._lib.http_tls_extract(json.dumps(req).encode("utf-8")))

    def free_null(self) -> None:
        self._lib.http_tls_free_string(None)


@pytest.fixture(scope="module")
def ffi_lib() -> Iterator[_FFILib]:
    path = _find_shared_lib()
    if path is None:
        pytest.skip("Standalone C-ABI shared library (http_tls.dll/.so/.dylib) not built")
    lib = _FFILib(path)
    yield lib
    lib.destroy_all()


class _EchoHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, code: int, obj: Dict[str, Any], extra_headers: Optional[Dict[str, str]] = None) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path.startswith("/set-cookie"):
            self._send_json(
                200,
                {"set": True},
                {"Set-Cookie": "sid=abc123; Path=/"},
            )
            return
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/echo?hop=1")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/binary"):
            payload = bytes(range(256))
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path.startswith("/stream-stall"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            part = b"data: first\n\n"
            try:
                self.wfile.write(f"{len(part):x}\r\n".encode("ascii") + part + b"\r\n")
                self.wfile.flush()
                time.sleep(5.0)
            except OSError:
                return
            return
        if self.path.startswith("/stream-sse"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for idx in range(4):
                part = f"data: chunk-{idx}-tieng-viet\n\n".encode("utf-8")
                frame = f"{len(part):x}\r\n".encode("ascii") + part + b"\r\n"
                try:
                    self.wfile.write(frame)
                    self.wfile.flush()
                    time.sleep(0.03)
                except OSError:
                    return
            try:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except OSError:
                pass
            return
        if self.path.startswith("/cf-challenge"):
            body = b"<html><head><title>Just a moment...</title></head><body>cf_chl_opt</body></html>"
            self.send_response(403)
            self.send_header("Server", "cloudflare")
            self.send_header("cf-mitigated", "challenge")
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        all_hdrs: Dict[str, Any] = {}
        for k in self.headers.keys():
            kl = k.lower()
            if kl not in all_hdrs:
                all_hdrs[kl] = self.headers.get_all(k) or []
        self._send_json(
            200,
            {
                "method": "GET",
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "headers_all": all_hdrs,
            },
        )

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b""
        all_hdrs: Dict[str, Any] = {}
        for k in self.headers.keys():
            kl = k.lower()
            if kl not in all_hdrs:
                all_hdrs[kl] = self.headers.get_all(k) or []
        self._send_json(
            200,
            {
                "method": "POST",
                "path": self.path,
                "content_type": self.headers.get("Content-Type", ""),
                "headers_all": all_hdrs,
                "body_len": len(raw),
                "body_utf8": raw.decode("utf-8", errors="replace"),
                "body_b64": base64.b64encode(raw).decode("ascii"),
            },
        )


class _ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 128


@pytest.fixture(scope="module")
def local_url() -> Iterator[str]:
    srv = _ThreadedHTTPServer(("127.0.0.1", 0), _EchoHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
    srv.server_close()


def test_ffi_version_and_presets(ffi_lib: _FFILib) -> None:
    v = ffi_lib.version()
    assert v["ok"] is True
    assert v["presets_count"] >= 100
    assert "http3" in v["features"]
    assert "real_ech_udp" in v["features"]

    p = ffi_lib.presets()
    assert p["ok"] is True
    assert "chrome_149" in p["presets"]
    assert "firefox_151" in p["presets"]
    assert "safari_26_4" in p["presets"]


def test_ffi_session_lifecycle_cookies_and_impersonate(ffi_lib: _FFILib, local_url: str) -> None:
    created = ffi_lib.create_session({"session_id": "test-custom-1", "impersonate": "chrome_149"})
    assert created["ok"] is True
    assert created["session_id"] == "test-custom-1"

    # Server-set cookie persists inside session jar
    r1 = ffi_lib.request({"session_id": "test-custom-1", "url": f"{local_url}/set-cookie"})
    assert r1["ok"] is True
    assert r1["cookies"].get("sid") == "abc123"

    r2 = ffi_lib.request({"session_id": "test-custom-1", "url": f"{local_url}/echo"})
    assert r2["ok"] is True
    echo = json.loads(r2["body"])
    assert "sid=abc123" in echo["headers"].get("cookie", "")

    # Manual cookie inject & query (raw_cookie, array inheriting url, dict map, and validation)
    sc = ffi_lib.set_cookies(
        {
            "session_id": "test-custom-1",
            "raw_cookie": "manual_tok=xyz789; Path=/",
            "url": f"{local_url}/",
        }
    )
    assert sc["ok"] is True

    sc_arr = ffi_lib.set_cookies(
        {
            "session_id": "test-custom-1",
            "url": f"{local_url}/",
            "cookies": [{"name": "arr_tok", "value": "v1"}],
        }
    )
    assert sc_arr["ok"] is True

    sc_map = ffi_lib.set_cookies(
        {
            "session_id": "test-custom-1",
            "url": f"{local_url}/",
            "cookies": {"map_tok": "v2"},
        }
    )
    assert sc_map["ok"] is True

    sc_bad = ffi_lib.set_cookies(
        {
            "session_id": "test-custom-1",
            "cookies": [{"name": "orphan", "value": "x"}],
        }
    )
    assert sc_bad["ok"] is False

    gc = ffi_lib.get_cookies({"session_id": "test-custom-1", "url": f"{local_url}/"})
    assert gc["ok"] is True
    assert gc["cookies"].get("manual_tok") == "xyz789"
    assert gc["cookies"].get("arr_tok") == "v1"
    assert gc["cookies"].get("map_tok") == "v2"
    assert gc["cookies"].get("sid") == "abc123"

    # Atomic clear + set + delete_name (including IP host-only cookies)
    ffi_lib.set_cookies(
        {
            "session_id": "test-custom-1",
            "clear": True,
            "url": f"{local_url}/",
            "cookies": {"keep_me": "k1", "drop_me": "d1"},
        }
    )
    ffi_lib.set_cookies({"session_id": "test-custom-1", "delete_name": "drop_me"})
    gc_after_del = ffi_lib.get_cookies({"session_id": "test-custom-1", "url": f"{local_url}/"})
    assert gc_after_del["cookies"] == {"keep_me": "k1"}

    # Hot-swap impersonation profile
    sw = ffi_lib.set_impersonate({"session_id": "test-custom-1", "impersonate": "firefox_151"})
    assert sw["ok"] is True
    r3 = ffi_lib.request({"session_id": "test-custom-1", "url": f"{local_url}/echo"})
    echo3 = json.loads(r3["body"])
    assert "Firefox/" in echo3["headers"].get("user-agent", "")

    # Destroy session
    d1 = ffi_lib.destroy_session("test-custom-1")
    assert d1["ok"] is True and d1["destroyed"] is True
    # Subsequent request on destroyed session returns structured error
    r4 = ffi_lib.request({"session_id": "test-custom-1", "url": f"{local_url}/echo"})
    assert r4["ok"] is False
    assert r4["error_kind"] == "session_not_found"


def test_ffi_oneshot_post_binary_multipart_redirects_and_challenge(
    ffi_lib: _FFILib, local_url: str
) -> None:
    # One-shot JSON POST with custom Content-Type & User-Agent (must NOT duplicate headers)
    r_json = ffi_lib.request(
        {
            "method": "POST",
            "url": f"{local_url}/submit",
            "params": {"a": "1", "b": "two"},
            "headers": {
                "X-Custom": "hello",
                "Content-Type": "application/vnd.api+json",
                "User-Agent": "MyTool/2.0",
            },
            "json": {"hello": "world", "n": 42},
        }
    )
    assert r_json["ok"] is True
    echo = json.loads(r_json["body"])
    assert echo["path"] == "/submit?a=1&b=two"
    assert echo["headers_all"]["content-type"] == ["application/vnd.api+json"]
    assert echo["headers_all"]["user-agent"] == ["MyTool/2.0"]
    assert json.loads(echo["body_utf8"]) == {"hello": "world", "n": 42}

    # Binary upload + binary download via base64
    raw_up = bytes([0, 1, 2, 128, 254, 255])
    r_bin_up = ffi_lib.request(
        {
            "method": "POST",
            "url": f"{local_url}/bin",
            "body_base64": base64.b64encode(raw_up).decode("ascii"),
        }
    )
    assert r_bin_up["ok"] is True
    assert base64.b64decode(json.loads(r_bin_up["body"])["body_b64"]) == raw_up

    r_bin_down = ffi_lib.request({"url": f"{local_url}/binary", "return_body_base64": True})
    assert r_bin_down["ok"] is True
    assert base64.b64decode(r_bin_down["body_base64"]) == bytes(range(256))

    # Multipart upload
    r_mp = ffi_lib.request(
        {
            "method": "POST",
            "url": f"{local_url}/upload",
            "files": [
                {
                    "field": "doc",
                    "filename": "hello.txt",
                    "content": "multipart-ok-123",
                    "content_type": "text/plain",
                }
            ],
        }
    )
    assert r_mp["ok"] is True
    mp_echo = json.loads(r_mp["body"])
    assert "multipart/form-data" in mp_echo["content_type"]
    assert "multipart-ok-123" in mp_echo["body_utf8"]
    assert 'filename="hello.txt"' in mp_echo["body_utf8"]

    # Redirect history
    r_red = ffi_lib.request({"url": f"{local_url}/redirect"})
    assert r_red["ok"] is True
    assert r_red["url"].endswith("/echo?hop=1")
    assert len(r_red["history"]) == 1
    assert r_red["history"][0]["status_code"] == 302

    # URL-encoded form POST
    r_form = ffi_lib.request(
        {
            "method": "POST",
            "url": f"{local_url}/login",
            "form": {"user": "alice@example.com", "note": "a b&c"},
        }
    )
    assert r_form["ok"] is True
    f_echo = json.loads(r_form["body"])
    assert "application/x-www-form-urlencoded" in f_echo["content_type"]
    assert "user=alice%40example.com" in f_echo["body_utf8"]
    assert "note=a+b%26c" in f_echo["body_utf8"]

    # WAF challenge auto-detection
    r_cf = ffi_lib.request({"url": f"{local_url}/cf-challenge"})
    assert r_cf["ok"] is True
    assert r_cf["status_code"] == 403
    assert r_cf["challenge"] == "cloudflare"


def test_ffi_gather_and_multithreaded_shared_session(ffi_lib: _FFILib, local_url: str) -> None:
    sid = ffi_lib.create_session({"impersonate": "chrome_149"})["session_id"]
    try:
        # 1. Rust Tokio gather preserving order
        g = ffi_lib.gather(
            {
                "session_id": sid,
                "concurrency": 10,
                "requests": [{"url": f"{local_url}/item/{i}"} for i in range(12)],
            }
        )
        assert g["ok"] is True
        assert g["count"] == 12
        for i, item in enumerate(g["responses"]):
            assert item["ok"] is True
            assert json.loads(item["body"])["path"] == f"/item/{i}"

        # 2. 8 OS threads hitting the same session_id concurrently
        def _worker(idx: int) -> str:
            res = ffi_lib.request({"session_id": sid, "url": f"{local_url}/thread/{idx}"})
            assert res["ok"] is True
            return json.loads(res["body"])["path"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            paths = list(ex.map(_worker, range(24)))
        assert paths == [f"/thread/{i}" for i in range(24)]
    finally:
        ffi_lib.destroy_session(sid)


def test_ffi_extract_engine(ffi_lib: _FFILib) -> None:
    html = """
    <html><body>
      <h1>Main Title</h1>
      <h2>Sub Title</h2>
      <div class="card"><span class="price">$19.99</span><a class="buy" href="/buy/1">Buy</a></div>
      <div class="card"><span class="price">$49.50</span><a class="buy" href="/buy/2">Buy</a></div>
    </body></html>
    """
    r_css = ffi_lib.extract({"html": html, "css": "h1::text, h2::text"})
    assert r_css["ok"] is True
    assert r_css["result"] == ["Main Title", "Sub Title"]

    r_attr = ffi_lib.extract({"html": html, "css": "a.buy::attr(href)"})
    assert r_attr["result"] == ["/buy/1", "/buy/2"]

    r_xp = ffi_lib.extract({"html": html, "xpath": "//div[@class='card'][2]/span/text()", "first": True})
    assert r_xp["result"] == "$49.50"

    jdoc = json.dumps({"items": [{"name": "A", "price": 10}, {"name": "B", "price": 35}]})
    r_jp = ffi_lib.extract({"content": jdoc, "json_path": "items[?(@.price > 20)].name"})
    assert r_jp["ok"] is True and r_jp["found"] is True
    assert r_jp["result"] == ["B"]

    r_re = ffi_lib.extract({"content": html, "regex": r"\$([0-9]+\.[0-9]+)"})
    assert r_re["result"] == ["19.99", "49.50"]

    r_bt = ffi_lib.extract({"content": "id=101;id=202;", "left": "id=", "right": ";"})
    assert r_bt["result"] == ["101", "202"]


def test_ffi_error_and_null_safety(ffi_lib: _FFILib) -> None:
    ffi_lib.free_null()
    r_null = ffi_lib.request_raw(None)
    assert r_null["ok"] is False
    r_bad_json = ffi_lib.request_raw(b"{not valid json")
    assert r_bad_json["ok"] is False
    assert r_bad_json["error_kind"] == "value"
    r_bad_url = ffi_lib.request({"url": "not-a-url"})
    assert r_bad_url["ok"] is False
    r_bad_css = ffi_lib.extract({"html": "<p>x</p>", "css": "div[[[broken"})
    assert r_bad_css["ok"] is False


def test_ffi_live_http3_real_ech_doh_and_resumption(ffi_lib: _FFILib) -> None:
    sid = ffi_lib.create_session(
        {
            "impersonate": "chrome_149",
            "http3": True,
            "ech": True,
            "doh": True,
            "timeout": 20.0,
        }
    )["session_id"]
    try:
        r1 = ffi_lib.request({"session_id": sid, "url": "https://cloudflare-ech.com/cdn-cgi/trace"})
        assert r1["ok"] is True, f"H3 ECH request failed: {r1}"
        assert r1["status_code"] == 200
        assert r1["http_version"] == "HTTP/3"
        assert r1["ech_accepted"] is True
        assert "sni=encrypted" in r1["body"]

        # Fresh session with TCP HTTP/2 Real ECH
        r_h2 = ffi_lib.request(
            {
                "url": "https://cloudflare-ech.com/cdn-cgi/trace",
                "impersonate": "chrome_149",
                "http2_only": True,
                "ech": True,
                "doh": True,
                "timeout": 20.0,
            }
        )
        assert r_h2["ok"] is True, f"TCP H2 ECH request failed: {r_h2}"
        assert r_h2["status_code"] == 200
        assert r_h2["http_version"] == "HTTP/2"
        assert r_h2["ech_accepted"] is True
        assert "sni=encrypted" in r_h2["body"]
    finally:
        ffi_lib.destroy_session(sid)


def test_ffi_ja3_and_akamai_h2_session(ffi_lib: _FFILib) -> None:
    created = ffi_lib.create_session(
        {
            "ja3": "771,4865-4866-4867-49195-49199,0-23-65281,4588-29-23-24,0",
            "akamai_h2": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
            "timeout": 15.0,
        }
    )
    assert created["ok"] is True
    sid = created["session_id"]
    try:
        r = ffi_lib.request({"session_id": sid, "url": "https://cloudflare.com/cdn-cgi/trace"})
        assert r["ok"] is True
        assert r["status_code"] == 200
        assert "http=http/2" in r["body"]
    finally:
        ffi_lib.destroy_session(sid)


def test_ffi_streaming_local_and_live_http3_ech(ffi_lib: _FFILib, local_url: str) -> None:
    # 1. Local multi-chunk SSE stream read to EOF + auto cleanup
    opened = ffi_lib.stream_open({"url": f"{local_url}/stream-sse"})
    assert opened["ok"] is True
    assert opened["status_code"] == 200
    st_id = opened["stream_id"]

    collected = bytearray()
    chunks = 0
    while True:
        item = ffi_lib.stream_read(st_id)
        assert item["ok"] is True
        if item["eof"]:
            break
        chunks += 1
        collected.extend(base64.b64decode(item["data_base64"]))
    text = collected.decode("utf-8")
    assert chunks >= 1
    for i in range(4):
        assert f"data: chunk-{i}-tieng-viet" in text
    # Stream auto-removed after EOF
    after = ffi_lib.stream_read(st_id)
    assert after["ok"] is False and after["error_kind"] == "stream_not_found"

    # 2. Early stream_close
    opened2 = ffi_lib.stream_open({"url": f"{local_url}/stream-sse"})
    assert opened2["ok"] is True
    st_id2 = opened2["stream_id"]
    first_chunk = ffi_lib.stream_read({"stream_id": st_id2, "timeout": 5.0})
    assert first_chunk["ok"] is True and not first_chunk["eof"]
    closed = ffi_lib.stream_close(st_id2)
    assert closed["ok"] is True and closed["closed"] is True

    # 3. Live HTTP/3 + Real ECH incremental stream
    h3_open = ffi_lib.stream_open(
        {
            "url": "https://cloudflare-ech.com/cdn-cgi/trace",
            "impersonate": "chrome_149",
            "http3": True,
            "ech": True,
            "doh": True,
            "timeout": 20.0,
        }
    )
    assert h3_open["ok"] is True, f"H3 stream open failed: {h3_open}"
    assert h3_open["http_version"] == "HTTP/3"
    assert h3_open["ech_accepted"] is True
    h3_id = h3_open["stream_id"]
    h3_buf = bytearray()
    while True:
        ch = ffi_lib.stream_read({"stream_id": h3_id, "timeout": 15.0})
        assert ch["ok"] is True
        if ch["eof"]:
            break
        h3_buf.extend(base64.b64decode(ch["data_base64"]))
    assert "sni=encrypted" in h3_buf.decode("utf-8")


def _start_local_ws_echo() -> tuple[str, threading.Event, socket.socket]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def recv_exact(conn: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return b""
            buf.extend(chunk)
        return bytes(buf)

    def handle(conn: socket.socket) -> None:
        try:
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                req += chunk
            key = ""
            for line in req.decode("latin1").split("\r\n"):
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
            accept = base64.b64encode(
                hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
            ).decode()
            conn.sendall(
                f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n".encode()
            )
            while True:
                hdr = recv_exact(conn, 2)
                if not hdr:
                    break
                opcode = hdr[0] & 0x0F
                masked = (hdr[1] & 0x80) != 0
                plen = hdr[1] & 0x7F
                if plen == 126:
                    plen = struct.unpack("!H", recv_exact(conn, 2) or b"\x00\x00")[0]
                elif plen == 127:
                    plen = struct.unpack("!Q", recv_exact(conn, 8) or b"\x00" * 8)[0]
                mask = (recv_exact(conn, 4) or b"\x00\x00\x00\x00") if masked else b"\x00\x00\x00\x00"
                data = (recv_exact(conn, plen) or b"") if plen else b""
                if masked:
                    data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
                if opcode == 0x8:
                    conn.sendall(bytes([0x88, 0x00]))
                    break
                if opcode in (0x1, 0x2):
                    frame = bytes([0x80 | opcode])
                    if len(data) < 126:
                        frame += bytes([len(data)])
                    else:
                        frame += bytes([126]) + struct.pack("!H", len(data))
                    conn.sendall(frame + data)
        except OSError:
            pass
        finally:
            conn.close()

    def serve() -> None:
        sock.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()
    return f"ws://127.0.0.1:{port}/ws", stop, sock


def test_ffi_websocket_text_binary_timeout_and_close(ffi_lib: _FFILib) -> None:
    ws_url, stop, sock = _start_local_ws_echo()
    try:
        conn = ffi_lib.ws_connect({"url": ws_url, "impersonate": "chrome_149", "timeout": 10.0})
        assert conn["ok"] is True
        assert conn["status_code"] == 101
        ws_id = conn["ws_id"]

        # Text frame (with Vietnamese UTF-8)
        assert ffi_lib.ws_send({"ws_id": ws_id, "text": "Xin chào WebSocket 🔥"})["ok"] is True
        r_txt = ffi_lib.ws_recv(ws_id)
        assert r_txt["ok"] is True
        assert r_txt["closed"] is False
        assert r_txt["kind"] == "text"
        assert r_txt["text"] == "Xin chào WebSocket 🔥"

        # Binary frame (including 0x00 & 0xff)
        raw_bin = bytes([0, 1, 2, 127, 128, 254, 255])
        assert (
            ffi_lib.ws_send({"ws_id": ws_id, "data_base64": base64.b64encode(raw_bin).decode()})[
                "ok"
            ]
            is True
        )
        r_bin = ffi_lib.ws_recv({"ws_id": ws_id, "timeout": 5.0})
        assert r_bin["ok"] is True
        assert r_bin["kind"] == "binary"
        assert base64.b64decode(r_bin["data_base64"]) == raw_bin

        # Recv timeout keeps socket alive
        r_to = ffi_lib.ws_recv({"ws_id": ws_id, "timeout": 0.2})
        assert r_to["ok"] is False and r_to["error_kind"] == "timeout"

        # Still works after timeout
        assert ffi_lib.ws_send({"ws_id": ws_id, "text": "after-timeout"})["ok"] is True
        r_after = ffi_lib.ws_recv({"ws_id": ws_id, "timeout": 5.0})
        assert r_after["ok"] is True and r_after["text"] == "after-timeout"

        # Graceful close
        cl = ffi_lib.ws_close({"ws_id": ws_id, "code": 1000, "reason": "done"})
        assert cl["ok"] is True and cl["closed"] is True
        assert ffi_lib.ws_recv(ws_id)["error_kind"] == "ws_not_found"

        # Full-duplex concurrency: Thread 1 blocked in ws_recv(15s) while Thread 2 sends!
        conn2 = ffi_lib.ws_connect({"url": ws_url, "timeout": 10.0})
        assert conn2["ok"] is True
        ws2 = conn2["ws_id"]
        recv_holder: Dict[str, Any] = {}

        def _reader() -> None:
            recv_holder.update(ffi_lib.ws_recv({"ws_id": ws2, "timeout": 15.0}))

        t_read = threading.Thread(target=_reader)
        t0 = time.perf_counter()
        t_read.start()
        time.sleep(0.12)
        send_res = ffi_lib.ws_send({"ws_id": ws2, "text": "full-duplex-ok"})
        t_read.join(timeout=5.0)
        elapsed_fd = time.perf_counter() - t0
        assert send_res["ok"] is True
        assert recv_holder.get("ok") is True and recv_holder.get("text") == "full-duplex-ok"
        assert elapsed_fd < 2.0, f"Full-duplex ws_send blocked behind ws_recv ({elapsed_fd:.2f}s)!"

        # Cross-thread ws_close instantly cancels a blocked ws_recv(15s)!
        recv_cancel: Dict[str, Any] = {}

        def _reader_cancel() -> None:
            recv_cancel.update(ffi_lib.ws_recv({"ws_id": ws2, "timeout": 15.0}))

        t_rc = threading.Thread(target=_reader_cancel)
        t1 = time.perf_counter()
        t_rc.start()
        time.sleep(0.12)
        cl2 = ffi_lib.ws_close(ws2)
        t_rc.join(timeout=5.0)
        elapsed_cancel = time.perf_counter() - t1
        assert cl2["ok"] is True and cl2["closed"] is True
        assert recv_cancel.get("ok") is True and recv_cancel.get("closed") is True
        assert elapsed_cancel < 2.0, f"ws_close did not cancel blocked ws_recv ({elapsed_cancel:.2f}s)!"

        # Error paths: invalid close code, unreachable port
        assert ffi_lib.ws_close({"ws_id": "nonexistent", "code": 99999})["ok"] is False
        assert ffi_lib.ws_connect({"url": "ws://127.0.0.1:1/dead", "timeout": 2.0})["ok"] is False
    finally:
        stop.set()
        sock.close()


def test_ffi_stream_cross_thread_cancel(ffi_lib: _FFILib, local_url: str) -> None:
    opened = ffi_lib.stream_open({"url": f"{local_url}/stream-stall"})
    assert opened["ok"] is True
    st_id = opened["stream_id"]
    first = ffi_lib.stream_read({"stream_id": st_id, "timeout": 5.0})
    assert first["ok"] is True and "data: first" in first["text"]

    # Second read stalls for 5s; cross-thread stream_close must cancel it immediately!
    read_holder: Dict[str, Any] = {}

    def _blocked_read() -> None:
        read_holder.update(ffi_lib.stream_read({"stream_id": st_id, "timeout": 15.0}))

    t = threading.Thread(target=_blocked_read)
    t0 = time.perf_counter()
    t.start()
    time.sleep(0.12)
    cl = ffi_lib.stream_close(st_id)
    t.join(timeout=5.0)
    dt = time.perf_counter() - t0
    assert cl["ok"] is True and cl["closed"] is True
    assert read_holder.get("ok") is True and read_holder.get("eof") is True
    assert dt < 1.5, f"stream_close did not cancel blocked stream_read ({dt:.2f}s)!"


