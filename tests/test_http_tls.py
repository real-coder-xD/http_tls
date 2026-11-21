# Python 3 | tests/test_http_tls.py | Standalone Rust + BoringSSL test suite for http_tls v0.4.0
from __future__ import annotations

import asyncio
import base64
import datetime
import hashlib
import json
import os
import socket
import struct
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import http_tls
import http_tls as requests
import http_tls as httpx
from http_tls import BrowserType, Response, Session, AsyncSession, exceptions as exc


# ---------------------------------------------------------------------------
# Local HTTP + RFC 6455 WebSocket test fixtures (zero external flakiness)
# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
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
            payload = {
                "method": "GET",
                "path": p,
                "cookie": self.headers.get("Cookie"),
                "ua": self.headers.get("User-Agent"),
                "auth": self.headers.get("Authorization"),
                "custom": self.headers.get("X-Custom"),
            }
            self._send(200, json.dumps(payload).encode(), [("Content-Type", "application/json")])
        elif p.startswith("/latin1"):
            self._send(200, "café".encode("iso-8859-1"), [("Content-Type", "text/plain; charset=ISO-8859-1")])
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
        elif p.startswith("/cf"):
            self._send(
                403,
                b"<html><title>Just a moment...</title>challenge-platform</html>",
                [("Server", "cloudflare"), ("cf-mitigated", "challenge")],
            )
        elif p.startswith("/status/"):
            code = int(p.split("/")[-1])
            self._send(code, b"status")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b""
        payload = {
            "content_type": self.headers.get("Content-Type"),
            "body": body.decode("utf-8", errors="replace"),
            "length": len(body),
        }
        self._send(200, json.dumps(payload).encode(), [("Content-Type", "application/json")])


def _start_ws_echo_server():
    """Minimal RFC 6455 WebSocket echo server on 127.0.0.1:0."""
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
            key = None
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
                    plen = struct.unpack("!H", recv_exact(conn, 2))[0]
                elif plen == 127:
                    plen = struct.unpack("!Q", recv_exact(conn, 8))[0]
                mask = recv_exact(conn, 4) if masked else b"\x00\x00\x00\x00"
                data = recv_exact(conn, plen) if plen else b""
                if masked:
                    data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
                if opcode == 0x8:  # close
                    conn.sendall(bytes([0x88, 0x00]))
                    break
                if opcode in (0x1, 0x2):  # text or binary echo
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

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return port, stop, sock


@pytest.fixture(scope="module")
def http_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture(scope="module")
def ws_server():
    port, stop, sock = _start_ws_echo_server()
    yield f"ws://127.0.0.1:{port}/ws"
    stop.set()
    sock.close()


# ---------------------------------------------------------------------------
# 1. Core HTTP, Cookies, Redirects, Deep cookies.clear()
# ---------------------------------------------------------------------------
def test_standalone_engine_mode():
    with Session(impersonate="chrome_152") as s:
        assert s.mode == "rust"
        assert len(http_tls.supported_presets()) >= 50


def test_redirects_cookies_and_deep_clear(http_server):
    with Session(impersonate="chrome_152") as s:
        r = s.get(f"{http_server}/set")
        assert r.status_code == 200
        data = r.json()
        assert data["path"] == "/echo"
        assert "a=1" in data["cookie"] and "b=2" in data["cookie"]
        assert s.cookies["a"] == "1" and s.cookies["b"] == "2"
        assert "Chrome/152" in (data["ua"] or "")

        # Per-request redirect disable
        r_no_redir = s.get(f"{http_server}/set", allow_redirects=False)
        assert r_no_redir.status_code == 302

        # Deep cookie clear wipes BOTH Python dict and Rust Jar
        s.cookies.clear()
        assert len(s.cookies) == 0
        r_after = s.get(f"{http_server}/echo")
        assert r_after.json()["cookie"] is None


def test_charset_auth_and_headers(http_server):
    with Session(auth=("alice", "secret"), headers={"X-Custom": "val123"}) as s:
        r = s.get(f"{http_server}/latin1")
        assert r.text == "café"
        r2 = s.get(f"{http_server}/echo")
        j = r2.json()
        assert j["custom"] == "val123"
        assert j["auth"].startswith("Basic ")


# ---------------------------------------------------------------------------
# 2. Multipart file uploads (`files=`)
# ---------------------------------------------------------------------------
def test_multipart_upload(http_server):
    with Session() as s:
        r = s.post(
            f"{http_server}/upload",
            data={"meta": "ok"},
            files={"doc": ("hello.txt", b"hello-rust-multipart", "text/plain")},
        )
        assert r.status_code == 200
        j = r.json()
        assert "multipart/form-data" in j["content_type"]
        assert "hello-rust-multipart" in j["body"]
        assert 'filename="hello.txt"' in j["body"]
        assert "meta" in j["body"]


# ---------------------------------------------------------------------------
# 3. Streaming (sync + native async)
# ---------------------------------------------------------------------------
def test_sync_streaming(http_server):
    with requests.get(f"{http_server}/stream", stream=True) as r:
        lines = list(r.iter_lines())
        assert lines == [f"line{i}".encode() for i in range(5)]

    with requests.get(f"{http_server}/stream", stream=True) as r:
        chunks = list(r.iter_content(chunk_size=4))
        assert b"".join(chunks) == b"".join(f"line{i}\n".encode() for i in range(5))
        assert all(len(c) <= 4 for c in chunks)


def test_async_native_tokio_and_streaming(http_server):
    async def run():
        async with httpx.AsyncClient(impersonate="chrome_149") as client:
            assert client.mode == "rust"
            # Fire 50 concurrent requests directly on Tokio (no thread pool)
            tasks = [client.get(f"{http_server}/echo?i={i}") for i in range(50)]
            resps = await asyncio.gather(*tasks)
            assert len(resps) == 50
            assert all(r.is_success for r in resps)

            # Native async streaming
            async with await client.get(f"{http_server}/stream", stream=True) as sr:
                lines = [line async for line in sr.aiter_lines()]
                assert lines == [f"line{i}" for i in range(5)]

    asyncio.run(run())


# ---------------------------------------------------------------------------
# 4. WebSocket (sync + native async)
# ---------------------------------------------------------------------------
def test_sync_and_async_websocket(ws_server):
    with Session(impersonate="chrome_149") as s:
        with s.ws_connect(ws_server) as ws:
            assert ws.status_code == 101
            ws.send_text("ping-sync")
            assert ws.recv_text() == "ping-sync"
            ws.send_bytes(b"\x01\x02\x03")
            kind, payload = ws.recv()
            assert kind == "binary" and payload == b"\x01\x02\x03"

    async def run_ws():
        async with AsyncSession(impersonate="chrome_149") as s:
            async with await s.ws_connect(ws_server) as ws:
                assert ws.status_code == 101
                await ws.send_json({"hello": "async"})
                assert await ws.recv_json() == {"hello": "async"}

    asyncio.run(run_ws())


# ---------------------------------------------------------------------------
# 5. httpx API, Exceptions & Challenge Detection
# ---------------------------------------------------------------------------
def test_httpx_api_exceptions_and_challenge(http_server):
    with httpx.Client(follow_redirects=True) as client:
        r200 = client.get(f"{http_server}/status/200")
        assert r200.is_success and not r200.is_error and r200.read() == b"status"

        r404 = client.get(f"{http_server}/status/404")
        assert r404.is_client_error and r404.is_error
        with pytest.raises(exc.HTTPError):
            r404.raise_for_status()

        rcf = client.get(f"{http_server}/cf")
        assert rcf.challenge == "cloudflare"
        assert r200.challenge is None

        with pytest.raises(exc.Timeout):
            client.get(f"{http_server}/slow", timeout=0.5)

        # Bind an ephemeral port and close it so the OS refuses cleanly
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dead:
            dead.bind(("127.0.0.1", 0))
            dead_port = dead.getsockname()[1]
        with pytest.raises(exc.ConnectionError):
            client.get(f"http://127.0.0.1:{dead_port}/", timeout=5)


# ---------------------------------------------------------------------------
# 6. TLS Custom CA, mTLS & Live BoringSSL JA4 Verification
# ---------------------------------------------------------------------------
@pytest.mark.skipif(os.environ.get("HTTP_TLS_OFFLINE") == "1", reason="Offline mode")
def test_standalone_boringssl_ja4_and_h2():
    """Verify byte-exact Chrome JA4 & HTTP/2 Akamai fingerprint WITHOUT curl_cffi."""
    with Session(impersonate="chrome_149", engine="rust", timeout=20) as s:
        assert s.mode == "rust"
        r = s.get("https://tls.peet.ws/api/all")
        assert r.status_code == 200
        assert r.http_version == "HTTP/2"
        j = r.json()
        ja4 = j["tls"]["ja4"]
        akamai = j["http2"]["akamai_fingerprint"]
        # Chrome TLS 1.3 + H2 + 15 ciphers + 16 extensions + Chrome Akamai m,a,s,p
        assert ja4.startswith("t13d1516h2_8daaf6152771_"), f"Unexpected JA4: {ja4}"
        assert "|m,a,s,p" in akamai, f"Unexpected Akamai H2: {akamai}"


@pytest.mark.skipif(os.environ.get("HTTP_TLS_OFFLINE") == "1", reason="Offline mode")
def test_custom_ca_and_mtls():
    import certifi
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    # Valid CA bundle passes
    with Session(verify=certifi.where(), timeout=15) as s:
        assert s.get("https://www.example.com/").status_code == 200

    # Bogus self-signed CA bundle must reject public cert with SSLError
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

        # Client cert (crt, key) accepted by BoringSSL identity loader
        with Session(cert=(crt_path, key_path), timeout=15) as s:
            assert s.get("https://www.example.com/").status_code == 200
