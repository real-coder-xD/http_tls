# Python 3 | tests/test_http_tls.py | Standalone Rust + BoringSSL test suite for http_tls v0.5.0
from __future__ import annotations

import asyncio
import base64
import datetime
import gc
import gzip
import hashlib
import json
import os
import re
import socket
import struct
import tempfile
import threading
import time
import tracemalloc
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import http_tls
import http_tls as requests
import http_tls as httpx
from http_tls import (
    AsyncSession,
    BearerAuth,
    BrowserType,
    DigestAuth,
    Session,
    exceptions as exc,
)


# ---------------------------------------------------------------------------
# Local HTTP + Digest + Flaky + RFC 6455 WebSocket test fixtures
# ---------------------------------------------------------------------------
_FLAKY_COUNTER = {"503": 0, "cf": 0}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args):
        pass

    def _send(self, code: int, body: bytes = b"", headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path
        if p.startswith("/set"):
            self._send(
                302,
                headers=[
                    ("Set-Cookie", "a=1; Path=/"),
                    ("Set-Cookie", "b=2; Path=/"),
                    ("Location", "/echo"),
                ],
            )
        elif p.startswith("/echo"):
            raw_order = [line.split(":", 1)[0] for line in str(self.headers).splitlines() if ":" in line]
            payload = {
                "method": "GET",
                "path": p,
                "host": self.headers.get("Host"),
                "cookie": self.headers.get("Cookie"),
                "ua": self.headers.get("User-Agent"),
                "auth": self.headers.get("Authorization"),
                "custom": self.headers.get("X-Custom"),
                "hook": self.headers.get("X-Hook"),
                "header_order": raw_order,
            }
            self._send(200, json.dumps(payload).encode(), [("Content-Type", "application/json")])
        elif p.startswith("/latin1"):
            self._send(200, "café".encode("iso-8859-1"), [("Content-Type", "text/plain; charset=ISO-8859-1")])
        elif p.startswith("/gzip"):
            raw = gzip.compress(b"compressed-gzip-payload-ok")
            self._send(200, raw, [("Content-Encoding", "gzip"), ("Content-Type", "text/plain")])
        elif p.startswith("/deflate"):
            raw = zlib.compress(b"compressed-deflate-payload-ok")
            self._send(200, raw, [("Content-Encoding", "deflate"), ("Content-Type", "text/plain")])
        elif p.startswith("/stream"):
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            for i in range(5):
                chunk = f"line{i}\n".encode()
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                self.wfile.flush()
                time.sleep(0.02)
            self.wfile.write(b"0\r\n\r\n")
        elif p.startswith("/slow"):
            time.sleep(2.5)
            self._send(200, b"late")
        elif p.startswith("/cf_flaky"):
            _FLAKY_COUNTER["cf"] += 1
            if _FLAKY_COUNTER["cf"] == 1:
                self._send(
                    403,
                    b"<html><title>Just a moment...</title>challenge-platform</html>",
                    [("Server", "cloudflare"), ("cf-mitigated", "challenge")],
                )
            else:
                self._send(200, b"passed-after-rotate")
        elif p.startswith("/cf"):
            self._send(
                403,
                b"<html><title>Just a moment...</title>challenge-platform</html>",
                [("Server", "cloudflare"), ("cf-mitigated", "challenge")],
            )
        elif p.startswith("/flaky"):
            _FLAKY_COUNTER["503"] += 1
            if _FLAKY_COUNTER["503"] <= 2:
                self._send(503, b"busy")
            else:
                self._send(200, b"recovered")
        elif p.startswith("/digest"):
            auth = self.headers.get("Authorization", "")
            realm, nonce, opaque = "test-realm", "abcdef123456", "op999"
            if not auth.startswith("Digest "):
                self._send(
                    401,
                    b"unauthorized",
                    [("WWW-Authenticate", f'Digest realm="{realm}", qop="auth", nonce="{nonce}", opaque="{opaque}", algorithm=SHA-256')],
                )
                return
            kv = {m.group(1).lower(): (m.group(2) if m.group(2) is not None else m.group(3))
                  for m in re.finditer(r'([a-zA-Z0-9_-]+)=(?:"([^"]*)"|([^\s,]*))', auth[7:])}
            h = lambda s: hashlib.sha256(s.encode()).hexdigest()
            ha1 = h(f"alice:{realm}:secret")
            ha2 = h(f"GET:{p}")
            expected = h(f"{ha1}:{nonce}:{kv['nc']}:{kv['cnonce']}:auth:{ha2}")
            if kv.get("response") == expected and kv.get("opaque") == opaque:
                self._send(200, b"digest-ok")
            else:
                self._send(403, b"bad-digest")
        elif p.startswith("/status/"):
            code = int(p.split("/")[-1])
            self._send(code, b"status")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        if self.path == "/redir307":
            length = int(self.headers.get("Content-Length", "0"))
            if length > 0:
                self.rfile.read(length)
            self._send(307, b"", [("Location", "/upload")])
            return
        if self.path == "/redir308":
            length = int(self.headers.get("Content-Length", "0"))
            if length > 0:
                self.rfile.read(length)
            self._send(308, b"", [("Location", "/upload")])
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b""
        payload = {
            "content_type": self.headers.get("Content-Type"),
            "body": body.decode("utf-8", errors="replace"),
            "length": len(body),
        }
        self._send(200, json.dumps(payload).encode(), [("Content-Type", "application/json")])


def _start_ws_echo_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def recv_exact(conn, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def handle(conn):
        try:
            raw = b""
            while b"\r\n\r\n" not in raw:
                c = conn.recv(4096)
                if not c:
                    return
                raw += c
            key = ""
            for line in raw.decode("latin1").split("\r\n"):
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
                    header = bytes([0x80 | opcode])
                    if len(data) < 126:
                        header += bytes([len(data)])
                    else:
                        header += bytes([126]) + struct.pack("!H", len(data))
                    conn.sendall(header + data)
        except Exception:
            pass
        finally:
            conn.close()

    def serve():
        sock.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()
    return port, stop, sock


@pytest.fixture(scope="module")
def http_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}", srv.server_port
    srv.shutdown()


@pytest.fixture(scope="module")
def ws_server():
    port, stop, sock = _start_ws_echo_server()
    yield f"ws://127.0.0.1:{port}/ws"
    stop.set()
    sock.close()


# ---------------------------------------------------------------------------
# 1. Core HTTP, Cookies, Redirect History, Deep cookies.clear()
# ---------------------------------------------------------------------------
def test_standalone_engine_mode():
    with Session(impersonate="chrome_152") as s:
        assert s.mode == "rust"
        assert len(http_tls.supported_presets()) >= 50


def test_redirects_history_cookies_and_deep_clear(http_server):
    base, _port = http_server
    with Session(impersonate="chrome_152") as s:
        r = s.get(f"{base}/set")
        assert r.status_code == 200
        assert len(r.history) == 1
        assert r.history[0].status_code == 302
        assert r.remote_addr is not None and r.remote_addr.startswith("127.0.0.1:")
        data = r.json()
        assert data["path"] == "/echo"
        assert "a=1" in data["cookie"] and "b=2" in data["cookie"]
        assert s.cookies["a"] == "1" and s.cookies["b"] == "2"
        assert "Chrome/152" in (data["ua"] or "")

        r_no_redir = s.get(f"{base}/set", allow_redirects=False)
        assert r_no_redir.status_code == 302 and r_no_redir.history == []

        s.cookies.clear()
        assert len(s.cookies) == 0
        assert s.get(f"{base}/echo").json()["cookie"] is None


# ---------------------------------------------------------------------------
# 2. Group 1: Header Order, DNS resolve, local_address, Custom TLS/JA3, tls_info
# ---------------------------------------------------------------------------
def test_header_order_dns_resolve_and_local_address(http_server):
    base, port = http_server
    # Custom DNS resolve: fake hostname routed directly to 127.0.0.1 with preserved Host header
    order = ["X-First", "X-Second", "User-Agent"]
    with Session(
        resolve={"origin-test.internal": "127.0.0.1"},
        local_address="127.0.0.1",
        header_order=order,
        headers={"X-Second": "2", "X-First": "1"},
    ) as s:
        r = s.get(f"http://origin-test.internal:{port}/echo")
        assert r.status_code == 200
        j = r.json()
        assert j["host"] == f"origin-test.internal:{port}"
        wire = j["header_order"]
        assert "X-First" in wire and "X-Second" in wire
        assert wire.index("X-First") < wire.index("X-Second")


def test_ja3_parser():
    ja3 = "771,4865-4866-4867-49195-49199,0-23-65281,29-23-24,0"
    opts = http_tls.parse_ja3_to_tls_options(ja3)
    assert opts["min_tls_version"] == "1.2"
    assert "TLS_AES_128_GCM_SHA256" in opts["cipher_list"]
    assert opts["curves_list"] == "X25519:P-256:P-384"


# ---------------------------------------------------------------------------
# 3. Group 2: base_url, Retries + Backoff + Challenge Rotation, Auth, Event Hooks
# ---------------------------------------------------------------------------
def test_base_url_bearer_and_digest_auth(http_server):
    base, _port = http_server
    with httpx.Client(base_url=base, auth=BearerAuth("tok-xyz")) as client:
        r = client.get("/echo")
        assert r.is_success and r.json()["auth"] == "Bearer tok-xyz"

    # Sync RFC 7616 SHA-256 DigestAuth
    with Session(base_url=base, auth=DigestAuth("alice", "secret")) as s:
        r = s.get("/digest")
        assert r.status_code == 200 and r.text == "digest-ok"

    # Async RFC 7616 SHA-256 DigestAuth
    async def run_digest():
        async with AsyncSession(base_url=base, auth=DigestAuth("alice", "secret")) as s:
            r = await s.get("/digest")
            assert r.status_code == 200 and r.text == "digest-ok"

    asyncio.run(run_digest())


def test_retries_and_challenge_rotation(http_server):
    base, _port = http_server
    _FLAKY_COUNTER["503"] = 0
    with Session(base_url=base, retries=3, retry_backoff=0.02) as s:
        r = s.get("/flaky")
        assert r.status_code == 200 and r.text == "recovered"
        assert _FLAKY_COUNTER["503"] == 3

    _FLAKY_COUNTER["cf"] = 0
    with Session(base_url=base, retries=2, retry_backoff=0.02, retry_on_challenge=True, rotate_impersonate=True) as s:
        r = s.get("/cf_flaky")
        assert r.status_code == 200 and r.text == "passed-after-rotate"
        assert _FLAKY_COUNTER["cf"] == 2


def test_event_hooks_sync_and_async(http_server):
    base, _port = http_server
    seen_statuses = []

    def add_header(req):
        req["headers"]["X-Hook"] = "injected-sync"

    def log_resp(resp):
        seen_statuses.append(resp.status_code)

    with httpx.Client(base_url=base, event_hooks={"request": [add_header], "response": [log_resp]}) as c:
        r = c.get("/echo")
        assert r.json()["hook"] == "injected-sync"
        assert seen_statuses == [200]

    async def run_async_hooks():
        async def async_req_hook(req):
            req["headers"]["X-Hook"] = "injected-async"

        async def async_resp_hook(resp):
            seen_statuses.append(resp.status_code)

        async with httpx.AsyncClient(
            base_url=base, event_hooks={"request": [async_req_hook], "response": [async_resp_hook]}
        ) as c:
            r = await c.get("/echo")
            assert r.json()["hook"] == "injected-async"

    asyncio.run(run_async_hooks())
    assert seen_statuses == [200, 200]


# ---------------------------------------------------------------------------
# 4. Multipart, Streaming, Native Tokio Async, WebSocket, Exceptions
# ---------------------------------------------------------------------------
def test_multipart_upload(http_server):
    base, _port = http_server
    with Session() as s:
        r = s.post(
            f"{base}/upload",
            data={"meta": "ok"},
            files={"doc": ("hello.txt", b"hello-rust-multipart", "text/plain")},
        )
        assert r.status_code == 200
        j = r.json()
        assert "multipart/form-data" in j["content_type"]
        assert "hello-rust-multipart" in j["body"]
        assert 'filename="hello.txt"' in j["body"]


def test_sync_streaming_and_native_async(http_server):
    base, _port = http_server
    with requests.get(f"{base}/stream", stream=True) as r:
        assert list(r.iter_lines()) == [f"line{i}".encode() for i in range(5)]

    async def run():
        async with httpx.AsyncClient(base_url=base, impersonate="chrome_149") as client:
            resps = await asyncio.gather(*[client.get(f"/echo?i={i}") for i in range(40)])
            assert len(resps) == 40 and all(r.is_success for r in resps)
            async with await client.get("/stream", stream=True) as sr:
                assert [line async for line in sr.aiter_lines()] == [f"line{i}" for i in range(5)]

    asyncio.run(run())


def test_sync_and_async_websocket(ws_server):
    with Session(impersonate="chrome_149") as s:
        with s.ws_connect(ws_server) as ws:
            assert ws.status_code == 101
            ws.send_text("ping-sync")
            assert ws.recv_text() == "ping-sync"
            ws.send_bytes(b"\x01\x02\x03")
            assert ws.recv() == ("binary", b"\x01\x02\x03")

    async def run_ws():
        async with AsyncSession(impersonate="chrome_149") as s:
            async with await s.ws_connect(ws_server) as ws:
                assert ws.status_code == 101
                await ws.send_json({"hello": "async"})
                assert await ws.recv_json() == {"hello": "async"}

    asyncio.run(run_ws())


def test_httpx_api_exceptions_and_challenge(http_server):
    base, _port = http_server
    with httpx.Client(base_url=base, follow_redirects=True) as client:
        r200 = client.get("/status/200")
        assert r200.is_success and not r200.is_error and r200.read() == b"status"

        r404 = client.get("/status/404")
        assert r404.is_client_error and r404.is_error
        with pytest.raises(exc.HTTPError):
            r404.raise_for_status()

        assert client.get("/cf").challenge == "cloudflare"
        assert r200.challenge is None

        with pytest.raises(exc.Timeout):
            client.get("/slow", timeout=0.5)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dead:
            dead.bind(("127.0.0.1", 0))
            dead_port = dead.getsockname()[1]
        with pytest.raises(exc.ConnectionError):
            client.get(f"http://127.0.0.1:{dead_port}/", timeout=5)


# ---------------------------------------------------------------------------
# 5. Live BoringSSL JA4, Custom TLS/HTTP1, TLS Peer Cert & Custom CA/mTLS
# ---------------------------------------------------------------------------
@pytest.mark.skipif(os.environ.get("HTTP_TLS_OFFLINE") == "1", reason="Offline mode")
def test_standalone_boringssl_ja4_h2_tls_info_and_http1():
    with Session(impersonate="chrome_149", tls_info=True, timeout=20) as s:
        r = s.get("https://tls.peet.ws/api/all")
        assert r.status_code == 200
        assert r.http_version == "HTTP/2"
        assert r.peer_certificate is not None and len(r.peer_certificate) > 200
        j = r.json()
        assert j["tls"]["ja4"].startswith("t13d1516h2_8daaf6152771_")
        assert "|m,a,s,p" in j["http2"]["akamai_fingerprint"]

    # Force HTTP/1.1 + custom JA3 string
    ja3 = "771,4865-4866-4867-49195-49199,0-23-65281,29-23-24,0"
    with Session(ja3=ja3, http1_only=True, timeout=15) as s:
        r = s.get("https://www.example.com/")
        assert r.status_code == 200
        assert r.http_version == "HTTP/1.1"


@pytest.mark.skipif(os.environ.get("HTTP_TLS_OFFLINE") == "1", reason="Offline mode")
def test_custom_ca_and_mtls():
    import certifi
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    with Session(verify=certifi.where(), timeout=15) as s:
        assert s.get("https://www.example.com/").status_code == 200

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bogus-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with tempfile.TemporaryDirectory() as tmp:
        ca_path = os.path.join(tmp, "bogus.pem")
        crt_path = os.path.join(tmp, "client.crt")
        key_path = os.path.join(tmp, "client.key")
        with open(ca_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(crt_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )

        with Session(verify=ca_path, timeout=15) as s:
            with pytest.raises(exc.SSLError):
                s.get("https://www.example.com/")

        with Session(cert=(crt_path, key_path), timeout=15) as s:
            assert s.get("https://www.example.com/").status_code == 200


# ---------------------------------------------------------------------------
# 6. Edge Cases: Compression, 307/308 POST Redirects, Proxy Pool, Stress/RAM
# ---------------------------------------------------------------------------
def test_compression_gzip_and_deflate(http_server):
    base, _port = http_server
    with Session(base_url=base) as s:
        rg = s.get("/gzip")
        assert rg.status_code == 200 and rg.text == "compressed-gzip-payload-ok"
        rd = s.get("/deflate")
        assert rd.status_code == 200 and rd.text == "compressed-deflate-payload-ok"


def test_redirect_307_and_308_preserve_post_body(http_server):
    base, _port = http_server
    with Session(base_url=base) as s:
        r307 = s.post("/redir307", json={"keep": "307-body"})
        assert r307.status_code == 200 and len(r307.history) == 1 and r307.history[0].status_code == 307
        assert '"keep"' in r307.json()["body"]

        r308 = s.post("/redir308", data="preserve-308-raw")
        assert r308.status_code == 200 and len(r308.history) == 1 and r308.history[0].status_code == 308
        assert r308.json()["body"] == "preserve-308-raw"


def test_local_http_proxy_and_proxy_pool_rotation():
    hits = {"p1": 0, "p2": 0}

    def make_proxy(tag):
        class ProxyHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args):
                pass

            def do_GET(self):
                hits[tag] += 1
                body = json.dumps({"via": tag, "target": self.path}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, f"http://127.0.0.1:{srv.server_port}"

    s1, p1 = make_proxy("p1")
    s2, p2 = make_proxy("p2")
    try:
        with Session(proxies_pool=[p1, p2], timeout=5) as s:
            r1 = s.get("http://example.invalid/one")
            r2 = s.get("http://example.invalid/two")
            r3 = s.get("http://example.invalid/three")
            assert r1.json()["via"] == "p1"
            assert r2.json()["via"] == "p2"
            assert r3.json()["via"] == "p1"
            assert hits["p1"] == 2 and hits["p2"] == 1
    finally:
        s1.shutdown()
        s2.shutdown()


def test_session_cookie_isolation_and_preset_families(http_server):
    base, _port = http_server
    with Session(base_url=base) as s1, Session(base_url=base) as s2:
        s1.get("/set")
        assert s1.cookies["a"] == "1"
        assert "a" not in s2.cookies
        assert s2.get("/echo").json()["cookie"] is None

    for preset in ("chrome_149", "edge_148", "safari_26_4", "firefox_151", "opera_131", "okhttp_5", "random", "weighted_random"):
        with Session(base_url=base, impersonate=preset) as s:
            r = s.get("/echo")
            assert r.status_code == 200 and r.json()["ua"]


def test_high_concurrency_stress_and_no_memory_leak(http_server):
    """Fire 300 concurrent native Tokio requests and verify bounded Python memory growth."""
    base, _port = http_server

    async def burst(n: int):
        async with httpx.AsyncClient(base_url=base, impersonate="chrome_149") as client:
            resps = await asyncio.gather(*[client.get(f"/echo?i={i}") for i in range(n)])
            assert len(resps) == n and all(r.is_success for r in resps)

    asyncio.run(burst(30))  # warmup
    gc.collect()
    tracemalloc.start()
    snap1 = tracemalloc.take_snapshot()
    asyncio.run(burst(300))
    gc.collect()
    snap2 = tracemalloc.take_snapshot()
    tracemalloc.stop()

    delta_bytes = sum(stat.size_diff for stat in snap2.compare_to(snap1, "lineno") if stat.size_diff > 0)
    # After GC, 300 concurrent completed requests must retain < 4 MB in Python heap
    assert delta_bytes < 4 * 1024 * 1024, f"Unexpected memory retention: {delta_bytes} bytes"


# ---------------------------------------------------------------------------
# 7. Endgame Features: Rust Sync gather(), storage_state, Auto-Solver, HAR & KeyLog
# ---------------------------------------------------------------------------
def test_sync_rust_gather_parallel_and_order(http_server):
    base, _port = http_server
    with Session(base_url=base, impersonate="chrome_149") as s:
        urls = [f"/echo?id={i}" for i in range(40)]
        resps = s.gather(urls, concurrency=20)
        assert len(resps) == 40
        assert [r.json()["path"] for r in resps] == urls

        # Mixed GET + POST spec dicts
        mixed = s.gather(
            [
                "/echo?step=1",
                {"method": "POST", "url": "/upload", "json": {"batch": True}},
            ],
            concurrency=5,
        )
        assert mixed[0].json()["path"] == "/echo?step=1"
        assert '"batch"' in mixed[1].json()["body"]


def test_storage_state_playwright_roundtrip_and_auto_solver(http_server):
    base, _port = http_server
    with tempfile.TemporaryDirectory() as tmp:
        state_file = os.path.join(tmp, "storage_state.json")
        with Session(base_url=base) as s1:
            s1.get("/set")
            s1.headers["User-Agent"] = "CustomCamoufox/1.0"
            saved = s1.save_storage_state(state_file)
            assert any(c["name"] == "a" and c["value"] == "1" for c in saved["cookies"])
            assert saved["user_agent"] == "CustomCamoufox/1.0"

        # Load storage_state into a brand-new Session
        with Session(base_url=base, storage_state=state_file) as s2:
            assert s2.cookies.get("a") == "1"
            assert s2.headers["User-Agent"] == "CustomCamoufox/1.0"
            echo = s2.get("/echo").json()
            assert echo["ua"] == "CustomCamoufox/1.0"
            assert "a=1" in echo["cookie"]

    # Custom challenge solver callback invoked automatically on retry_on_challenge
    _FLAKY_COUNTER["cf"] = 0
    solved_calls = []

    def fake_harvester(url, resp):
        solved_calls.append((url, resp.challenge))
        return {
            "cookies": [{"name": "cf_clearance", "value": "cleared-token-999", "domain": "127.0.0.1", "path": "/"}],
            "user_agent": "HarvesterBrowser/149.0",
        }

    with Session(base_url=base, retries=1, retry_backoff=0.01, retry_on_challenge=True, solver=fake_harvester) as s:
        r = s.get("/cf_flaky")
        assert r.status_code == 200
        assert len(solved_calls) == 1 and solved_calls[0][1] == "cloudflare"
        assert s.cookies["cf_clearance"] == "cleared-token-999"


def test_har_recording_and_export(http_server):
    base, _port = http_server
    with tempfile.TemporaryDirectory() as tmp:
        har_path = os.path.join(tmp, "trace.har")
        with Session(base_url=base, record_har=True) as s:
            s.get("/echo?har=1")
            s.post("/upload", json={"har": 2})
            har = s.export_har(har_path)
            assert har["log"]["version"] == "1.2"
            assert len(har["log"]["entries"]) == 2
            assert har["log"]["entries"][0]["request"]["method"] == "GET"
            assert har["log"]["entries"][1]["request"]["method"] == "POST"
            assert os.path.exists(har_path)
            s.clear_har()
            assert len(s.har_entries) == 0


@pytest.mark.skipif(os.environ.get("HTTP_TLS_OFFLINE") == "1", reason="Offline mode")
def test_tls_keylog_file_and_hickory_dns():
    with tempfile.TemporaryDirectory() as tmp:
        kl_path = os.path.join(tmp, "sslkeys.log")
        with Session(impersonate="chrome_149", keylog_file=kl_path, timeout=15) as s:
            r = s.get("https://www.example.com/")
            assert r.status_code == 200
        # Give async keylog writer channel a brief moment to flush
        time.sleep(0.1)
        assert os.path.exists(kl_path) and os.path.getsize(kl_path) > 0


# ---------------------------------------------------------------------------
# 8. Complete Drop-in API Parity (httpx / requests / curl_cffi methods & aliases)
# ---------------------------------------------------------------------------
def test_dropin_api_completeness_httpx_requests_cffi(http_server):
    base, _port = http_server

    # requests.session() factory + session-level default params + cookies.get_dict() + is_closed
    s = requests.session(base_url=base, params={"api_key": "k1"})
    assert not s.is_closed
    r = s.get("/echo", params={"page": "2"})
    assert "api_key=k1" in r.json()["path"] and "page=2" in r.json()["path"]
    assert r.reason_phrase == "OK"
    assert r.num_bytes_downloaded == len(r.content) and r.num_bytes_downloaded > 0

    s.get("/set")
    assert s.cookies.get_dict()["a"] == "1"

    # Redirect inspection properties + RFC 8288 Link header parser
    r302 = s.get("/set", allow_redirects=False)
    assert r302.has_redirect_location and not r302.is_permanent_redirect
    r_link = http_tls.Response(
        200,
        {"Link": '<https://api.example.com/items?page=2>; rel="next", <https://api.example.com/items?page=5>; rel="last"'},
        "https://api.example.com/items?page=1",
        b"[]",
        "[]",
    )
    assert r_link.links["next"]["url"] == "https://api.example.com/items?page=2"
    assert r_link.links["last"]["url"] == "https://api.example.com/items?page=5"

    # httpx.stream() & client.stream() sync context managers + iter_bytes() / iter_text()
    with httpx.stream("GET", f"{base}/stream") as sr:
        raw = b"".join(sr.iter_bytes(chunk_size=6))
        assert raw.startswith(b"line0\n") and sr.num_bytes_downloaded == len(raw)

    with s.stream("GET", "/stream") as sr2:
        txt = "".join(sr2.iter_text(chunk_size=6))
        assert "line4" in txt

    s.close()
    assert s.is_closed

    # Exception aliases (httpx + curl_cffi)
    assert http_tls.HTTPStatusError is http_tls.HTTPError
    assert http_tls.ConnectError is http_tls.ConnectionError
    assert http_tls.TimeoutException is http_tls.Timeout
    assert http_tls.RequestError is http_tls.RequestException
    assert http_tls.RequestsError is http_tls.RequestException

    # AsyncClient: stream(), aiter_content(), aiter_text(), acontent(), atext(), aclose(), is_closed
    async def run_async_dropin():
        client = httpx.AsyncClient(base_url=base, params={"v": "1"})
        assert not client.is_closed
        async with client.stream("GET", "/stream") as sr:
            chunks = [c async for c in sr.aiter_content(chunk_size=5)]
            assert b"".join(chunks).startswith(b"line0\n")
            assert sr.num_bytes_downloaded == len(b"".join(chunks))

        async with client.stream("GET", "/stream") as sr2:
            txt_chunks = [t async for t in sr2.aiter_text(chunk_size=5)]
            assert "line3" in "".join(txt_chunks)

        async with client.stream("GET", "/echo") as sr3:
            body_text = await sr3.atext()
            body_bytes = await sr3.acontent()
            assert "v=1" in body_text and len(body_bytes) > 0

        await client.aclose()
        assert client.is_closed

    asyncio.run(run_async_dropin())
