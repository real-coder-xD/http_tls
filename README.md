# http_tls

Standalone Rust and BoringSSL HTTP client for Python with byte-exact TLS (JA3/JA4) and HTTP/2 browser impersonation, native Tokio async I/O, parallel synchronous batching, streaming, multipart uploads, WebSockets, and reverse-engineering utilities.

Drop-in compatible with `requests`, `httpx`, and `curl_cffi` — distributed as a self-contained ABI3 wheel (~4.3 MB) for Python 3.8 through 3.14+ with zero external C runtime dependencies.

[![CI & Release Wheels](https://github.com/real-coder-xD/http_tls/actions/workflows/release.yml/badge.svg)](https://github.com/real-coder-xD/http_tls/actions)
[![PyPI version](https://img.shields.io/pypi/v/http-tls.svg)](https://pypi.org/project/http-tls/)
[![Python versions](https://img.shields.io/badge/python-3.8%20--%203.14-blue.svg)](https://pypi.org/project/http-tls/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[English Documentation](#overview) | [Tiếng Việt](#hướng-dẫn-tiếng-việt)

---

## Table of Contents

- [Overview](#overview)
- [Feature Comparison](#feature-comparison)
- [Benchmarks & Fingerprint Verification](#benchmarks--fingerprint-verification)
- [Installation](#installation)
- [Quick Start: Drop-in Modes](#quick-start-drop-in-modes)
- [Parallel Execution: Native Async & Sync `gather()`](#parallel-execution-native-async--sync-gather)
- [Streaming & Multipart Uploads](#streaming--multipart-uploads)
- [TLS-Impersonated WebSockets](#tls-impersonated-websockets)
- [Custom JA3, TLS Options, HTTP/2 & Exact Header Order](#custom-ja3-tls-options-http2--exact-header-order)
- [Proxies, Custom DNS (`resolve`), IPv6 Binding & Hickory DNS](#proxies-custom-dns-resolve-ipv6-binding--hickory-dns)
- [Authentication, Custom CA Bundles & mTLS](#authentication-custom-ca-bundles--mtls)
- [Anti-Bot Detection, Retries, Playwright `storage_state` & Solver Bridge](#anti-bot-detection-retries-playwright-storage_state--solver-bridge)
- [Reverse Engineering: Wireshark KeyLog & HAR 1.2 Export](#reverse-engineering-wireshark-keylog--har-12-export)
- [Supported Browser Presets](#supported-browser-presets)
- [API Reference Summary](#api-reference-summary)
- [Testing & Development](#testing--development)
- [Hướng dẫn Tiếng Việt](#hướng-dẫn-tiếng-việt)
- [License](#license)

---

## Overview

Standard Python HTTP libraries (`requests`, `urllib3`, `aiohttp`, `httpx`) rely on the system OpenSSL stack, exposing bot-identifiable TLS ClientHello signatures (JA3/JA4) and HTTP/2 `SETTINGS` frames that trigger immediate blocks from Cloudflare, Akamai, DataDome, PerimeterX, and Fastly.

`http_tls` embeds **BoringSSL (`btls`)**, a customizable **HTTP/2** engine, **Hickory async DNS**, and a process-wide **Tokio** runtime directly inside a compiled Rust PyO3 extension (`wreq` + `wreq-util`):

- **Standalone BoringSSL Fingerprinting:** Produces byte-accurate JA3, JA4, GREASE, ALPS, Post-Quantum `X25519MLKEM768`, and Akamai HTTP/2 frame fingerprints for 100+ browser profiles with no external `libcurl` or Go shared-library dependencies.
- **Triple API Compatibility:** Drop directly into codebases written for `requests` (`Session`, `session()`, `codes`), `httpx` (`Client`, `AsyncClient`, `base_url`, `stream()`, `aclose()`, `event_hooks`), or `curl_cffi` (`BrowserType`, `impersonate=`).
- **True Native Async & Sync Parallelism:** `AsyncSession` maps Rust Tokio futures directly onto Python's `asyncio` loop via `pyo3-async-runtimes` (no `asyncio.to_thread` thread-pool bottleneck). For synchronous scripts, `session.gather()` executes hundreds of requests concurrently inside Rust while releasing the GIL.
- **Memory Safe:** Built on Rust ownership/RAII with a shared Tokio runtime — no CGo garbage-collector pauses or long-running memory leaks.

---

## Feature Comparison

| Capability | `http_tls` | `curl_cffi` | `primp` / `rnet` | `tls-client` | `httpx` | `requests` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Standalone BoringSSL TLS / JA4 | Yes (100+ presets) | Yes | Yes | Go `utls` | No | No |
| Custom JA3, TLS & H2 Options | Yes | Yes | Partial | Yes | No | No |
| Exact Wire Header Order (`OrigHeaderMap`) | Yes | Partial | Yes | Yes | No | No |
| Native Event-Loop Async | Yes (Tokio) | Yes (libcurl) | Yes (Tokio) | No | Yes | No |
| Sync Parallel `gather()` (No `async/await`) | Yes (Rust Tokio) | No | No | No | No | No |
| `requests` + `httpx` + `curl_cffi` Drop-in | Yes | Partial | No | No | `httpx` only | `requests` only |
| Async Hickory DNS & `resolve` Override | Yes | `resolve` only | Partial | No | No | No |
| Local IPv4 / IPv6 `/64` Socket Binding | Yes | Yes | Partial | No | Partial | No |
| TLS-Impersonated WebSockets (Sync & Async) | Yes | Yes | Yes | No | No | No |
| Streaming, Multipart, Custom CA, mTLS | Yes | Yes | Partial | Partial | Yes | Yes |
| RFC 7616 `DigestAuth` (MD5/SHA-256/512) | Yes | No | No | No | Yes | Yes |
| Deep `cookies.clear()` Sync | Yes | Yes | Yes | Broken | Yes | Yes |
| Built-in WAF `resp.challenge` Detector | Yes | No | No | No | No | No |
| Playwright `storage_state.json` & Solver Bridge | Yes | No | No | No | No | No |
| Wireshark `keylog_file` & HAR 1.2 Export | Yes | No | No | No | No | No |
| Memory Safety (No CGo / Manual Free) | Rust RAII | C/CFFI | Rust RAII | Go CGo leaks | Python | Python |

---

## Benchmarks & Fingerprint Verification

### 1. Multi-Browser Fingerprint Audit (`https://tls.peet.ws/api/all`)

Verified using the standalone Rust BoringSSL engine (`engine="rust"`, no `curl_cffi`):

| Preset | Protocol | JA4 Fingerprint | Akamai HTTP/2 Fingerprint |
| :--- | :--- | :--- | :--- |
| `chrome_149` | HTTP/2 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `edge_148` | HTTP/2 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `safari_26_4` | HTTP/2 | `t13d2014h2_a09f3c656075_e42f34c56612` | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` |
| `firefox_151` | HTTP/2 | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` |
| `opera_131` | HTTP/2 | `t13d1516h2_8daaf6152771_02713d6af862` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `okhttp_5` | HTTP/2 | `t13d1613h2_46e7e9700bed_eca864cca44a` | `4:16777216\|16711681\|0\|m,p,a,s` |

### 2. Throughput & Python Heap Usage (`https://www.cloudflare.com/cdn-cgi/trace`)

Reproduce locally with `python benchmarks/bench_vs_competitors.py`:

**Sequential Sync (15 requests, warm connection):**

| Library | Median Latency | Throughput | Peak Python Memory (`tracemalloc`) |
| :--- | ---: | ---: | ---: |
| `http_tls` (Rust BoringSSL) | 38.0 ms | 24.4 req/s | 16.4 KB |
| `curl_cffi` | 47.2 ms | 10.4 req/s | 19.2 KB |
| `httpx` (HTTP/2, no TLS spoof) | 40.0 ms | 15.7 req/s | 249.3 KB |
| `requests` (HTTP/1.1) | 46.6 ms | 22.1 req/s | 170.7 KB |

**Concurrent Async (30 simultaneous requests):**

| Library | Average per Request | Throughput | Peak Python Memory (`tracemalloc`) |
| :--- | ---: | ---: | ---: |
| `http_tls.AsyncSession` (Tokio) | 2.9 ms | 346.0 req/s | 200.0 KB |
| `curl_cffi.AsyncSession` | 4.7 ms | 211.4 req/s | 234.6 KB |
| `httpx.AsyncClient` | 6.5 ms | 153.0 req/s | 525.0 KB |

---

## Installation

Prebuilt ABI3 wheels are published on PyPI for Windows (`x86_64`), Linux (`manylinux_2_28` `x86_64` and `aarch64`), and macOS (`x86_64` and `arm64`):

```bash
pip install http-tls
```

To upgrade to the latest release:

```bash
pip install -U http-tls
```

### Building from Source

Requires Rust (`>= 1.98`), `cmake`, `perl`, `clang`/`libclang` (and `nasm` on Windows):

```bash
git clone https://github.com/real-coder-xD/http_tls.git
cd http_tls
pip install maturin
maturin build --release --out dist
pip install dist/*.whl
```

---

## Quick Start: Drop-in Modes

### 1. Drop-in for `requests`

```python
import http_tls as requests

resp = requests.get("https://httpbin.org/get", timeout=10)
resp.raise_for_status()

print(resp.status_code == requests.codes.ok)  # True
print(bool(resp.ok), resp.reason)             # True OK
print(resp.headers["content-type"])           # Case-insensitive lookup

with requests.session(params={"format": "json"}) as s:
    s.get("https://httpbin.org/cookies/set?token=abc")
    print(s.cookies.get_dict())               # {'token': 'abc'}

    # Deep-clear removes cookies from both Python dict and Rust cookie jar
    s.cookies.clear()
    print(s.get("https://httpbin.org/cookies").json()["cookies"])  # {}
```

### 2. Drop-in for `httpx`

```python
import asyncio
import http_tls as httpx

with httpx.Client(
    base_url="https://httpbin.org",
    follow_redirects=True,
    impersonate="chrome_149",
) as client:
    r = client.get("/status/200")
    print(r.is_success, r.reason_phrase, r.http_version, r.remote_addr)

    with client.stream("GET", "/stream/5") as sr:
        for chunk in sr.iter_text(chunk_size=128):
            print(chunk, end="")
        print("\nDownloaded bytes:", sr.num_bytes_downloaded)

async def main():
    client = httpx.AsyncClient(base_url="https://httpbin.org", impersonate="chrome_149")
    try:
        r = await client.get("/get")
        print(r.status_code, len(await r.aread()))
    finally:
        await client.aclose()
        assert client.is_closed

asyncio.run(main())
```

### 3. Drop-in for `curl_cffi`

```python
from http_tls import requests, BrowserType

resp = requests.get(
    "https://tls.peet.ws/api/all",
    impersonate=BrowserType.chrome149,
)
print(resp.status_code, resp.json()["tls"]["ja4"])
```

---

## Parallel Execution: Native Async & Sync `gather()`

### Native Tokio Async (`AsyncSession` / `AsyncClient`)

```python
import asyncio
import http_tls

async def main():
    async with http_tls.AsyncSession(impersonate="chrome_149") as session:
        urls = [f"https://httpbin.org/anything?id={i}" for i in range(50)]
        responses = await asyncio.gather(*(session.get(u) for u in urls))
        print(f"Completed {len(responses)} requests")

asyncio.run(main())
```

### Parallel Sync Batching (`session.gather` — No `async/await` Required)

`gather()` dispatches a batch of URLs or request dictionaries directly onto the Rust Tokio multi-thread runtime while releasing the GIL, returning `List[Response]` in the exact input order:

```python
import http_tls

with http_tls.Session(base_url="https://httpbin.org", impersonate="chrome_149") as s:
    # Plain URL list
    responses = s.gather([f"/anything?i={i}" for i in range(50)], concurrency=25)

    # Mixed methods and payloads
    mixed = s.gather(
        [
            "/get?page=1",
            {"method": "POST", "url": "/post", "json": {"batch": True}},
            {"method": "GET", "url": "/headers", "headers": {"X-Trace": "1"}},
        ],
        concurrency=10,
    )
```

---

## Streaming & Multipart Uploads

### Sync & Async Streaming

```python
import asyncio
import http_tls

# Top-level context manager (httpx style)
with http_tls.stream("GET", "https://httpbin.org/bytes/4096") as resp:
    with open("output.bin", "wb") as f:
        for chunk in resp.iter_bytes(chunk_size=1024):
            f.write(chunk)

# Async streaming with line iteration
async def stream_lines():
    async with http_tls.AsyncClient() as client:
        async with client.stream("GET", "https://httpbin.org/stream/10") as resp:
            async for line in resp.aiter_lines():
                print(line)

asyncio.run(stream_lines())
```

### Multipart Uploads (`files=`)

```python
import http_tls

with http_tls.Session() as s:
    resp = s.post(
        "https://httpbin.org/post",
        data={"description": "report"},
        files={
            "file": ("report.txt", b"payload-bytes", "text/plain"),
        },
    )
    print(resp.status_code)
```

---

## TLS-Impersonated WebSockets

Both synchronous and native async WebSocket connections inherit the session's BoringSSL TLS fingerprint, proxy, and headers:

```python
import asyncio
import http_tls

# Synchronous WebSocket
with http_tls.Session(impersonate="chrome_149") as s:
    with s.ws_connect("wss://echo.websocket.org") as ws:
        ws.send_text("hello")
        print(ws.recv_text())
        ws.send_json({"event": "ping"})
        print(ws.recv_json())

# Native Async WebSocket
async def ws_async():
    async with http_tls.AsyncSession(impersonate="chrome_149") as s:
        async with await s.ws_connect("wss://echo.websocket.org") as ws:
            await ws.send_bytes(b"\x01\x02\x03")
            kind, data = await ws.recv()
            print(kind, data)

asyncio.run(ws_async())
```

---

## Custom JA3, TLS Options, HTTP/2 & Exact Header Order

For mobile APIs or non-standard clients, override TLS, HTTP/2 parameters, and exact wire header casing/order:

```python
import http_tls

with http_tls.Session(
    # Standard 5-field JA3 string
    ja3="771,4865-4866-4867-49195-49199,0-23-65281,29-23-24,0",
    # Fine-grained BoringSSL options
    tls_options={
        "alpn": ["h2", "http/1.1"],
        "grease_enabled": True,
        "permute_extensions": True,
        "enable_ech_grease": True,
        "enable_ocsp_stapling": True,
    },
    # Custom HTTP/2 SETTINGS
    http2_options={
        "header_table_size": 65536,
        "enable_push": False,
        "initial_window_size": 6291456,
        "max_header_list_size": 262144,
    },
    # Lock exact wire header order and casing
    header_order=["Host", "Connection", "User-Agent", "Accept", "Accept-Language"],
    # Protocol forcing (optional): http1_only=True or http2_only=True
) as s:
    resp = s.get("https://tls.peet.ws/api/all")
```

---

## Proxies, Custom DNS (`resolve`), IPv6 Binding & Hickory DNS

```python
import http_tls

# Single HTTP / HTTPS / SOCKS5 proxy
r = http_tls.get("https://api.ipify.org?format=json", proxy="socks5://user:pass@1.2.3.4:1080")

# Custom DNS / Origin IP override (keeps SNI and Host header intact)
with http_tls.Session(
    resolve={"api.example.com": "93.184.216.34"},
    # Bind outbound source IP (useful for rotating an IPv6 /64 subnet without proxies)
    local_address="2001:db8::42",
    # On Linux/macOS: interface="eth0"
    # Async Hickory DNS is enabled by default; pass system_dns=True to use OS resolver
) as s:
    r = s.get("https://api.example.com/health")
    print("Connected to:", r.remote_addr)
```

---

## Authentication, Custom CA Bundles & mTLS

```python
import http_tls
from http_tls import BasicAuth, BearerAuth, DigestAuth

# Basic, Bearer, and RFC 7616 Digest Auth (MD5, SHA-256, SHA-512 — sync & async)
with http_tls.Session(auth=DigestAuth("alice", "secret")) as s:
    r = s.get("https://httpbin.org/digest-auth/auth/alice/secret/SHA-256")

# Custom Root CA bundle (corporate proxy / self-signed CA)
with http_tls.Session(verify="/path/to/custom_ca_bundle.pem", tls_info=True) as s:
    r = s.get("https://internal.corp.local")
    print("Server leaf cert DER bytes:", len(r.peer_certificate or b""))

# Mutual TLS (client certificate + PKCS#8 private key, or single combined PEM)
with http_tls.Session(cert=("client.crt", "client.key")) as s:
    r = s.get("https://mtls.example.com")
```

---

## Anti-Bot Detection, Retries, Playwright `storage_state` & Solver Bridge

### 1. Automatic Challenge Detection & Resilience

`resp.challenge` inspects status codes, headers, and challenge markers to detect interstitials from `cloudflare`, `ddos-guard`, `datadome`, `perimeterx`, `imperva`, `sucuri`, `vercel`, and `akamai`:

```python
import http_tls

with http_tls.Session(
    impersonate="chrome_149",
    retries=3,
    retry_backoff=0.5,
    retry_on_challenge=True,
    rotate_impersonate=True,  # rotates to market-share weighted_random on retry
    proxies_pool=[
        "http://user:pass@proxy1.example.com:8080",
        "http://user:pass@proxy2.example.com:8080",
    ],
) as s:
    resp = s.get("https://protected.example.com")
    if resp.challenge:
        print("Blocked by:", resp.challenge)
```

### 2. Playwright / Camoufox `storage_state.json` & Solver Bridge

Share authenticated clearance sessions (`cf_clearance`, cookies, `User-Agent`) directly with Playwright or Camoufox, or wire up a FlareSolverr / custom browser solver callback:

```python
import http_tls

# Load cookies + User-Agent exported by Playwright context.storage_state(path="state.json")
with http_tls.Session(storage_state="state.json", impersonate="firefox_151") as s:
    resp = s.get("https://protected.example.com/api/data")
    s.save_storage_state("state.json")

# Automatic FlareSolverr or custom solver callback when a JS challenge occurs
with http_tls.Session(
    retries=1,
    retry_on_challenge=True,
    flare_solverr_url="http://localhost:8191/v1",
) as s:
    resp = s.get("https://protected.example.com")
```

### 3. Event Hooks (`request` / `response`)

```python
import http_tls

def sign_request(ctx):
    ctx["headers"]["X-Signature"] = "signed"

def log_response(resp):
    print(f"{resp.status_code} {resp.url} ({resp.elapsed * 1000:.1f} ms)")

with http_tls.Client(event_hooks={"request": [sign_request], "response": [log_response]}) as c:
    c.get("https://httpbin.org/get")
```

---

## Reverse Engineering: Wireshark KeyLog & HAR 1.2 Export

```python
import http_tls

with http_tls.Session(
    impersonate="chrome_149",
    keylog_file="sslkeys.log",  # Or set SSLKEYLOGFILE env var to decrypt TLS in Wireshark
    record_har=True,            # Record all traffic into HAR 1.2 format
) as s:
    s.get("https://httpbin.org/get")
    s.post("https://httpbin.org/post", json={"test": 1})
    s.export_har("session_trace.har")  # Drag-and-drop into Chrome DevTools Network tab
```

---

## Supported Browser Presets

Inspect the full list at runtime via `http_tls.supported_presets()`:

- **Chrome (`chrome_100` to `chrome_152`):** Including `chrome_152_macos`, `chrome_151_macos`, `chrome_131_android`, and dynamic forward-version header patching.
- **Edge (`edge_101` to `edge_152`):** `edge_152`, `edge_148`, `edge_147`, `edge_145`, `edge_142`, `edge_134`, `edge_131`, `edge_127`, `edge_122`, `edge_101`.
- **Safari (`safari_15_3` to `safari_27`):** Desktop (`safari_27`, `safari_26_4`, `safari_18_5`, `safari_18`, `safari_17`), iOS (`safari_ios_26_2`, `safari_ios_26`, `safari_ios_18_1_1`), and iPadOS (`safari_ipad_26`, `safari_ipad_18`).
- **Firefox (`firefox_109` to `firefox_155`):** Including `firefox_private_136` and `firefox_android_135`.
- **Opera (`opera_116` to `opera_131`):** `opera_131`, `opera_130`, `opera_128`, `opera_124`, `opera_120`, `opera_116`.
- **OkHttp (Android):** `okhttp_5`, `okhttp_4_12`, `okhttp_4_10`, `okhttp_4_9`, `okhttp_3_14`, `okhttp_3_11`.
- **Tor & Rotation:** `tor_14_5`, `random`, `weighted_random` (market-share weighted browser + OS selection).

---

## API Reference Summary

### `Session` / `Client` / `AsyncSession` / `AsyncClient` Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `impersonate` | `str \| BrowserType` | `"chrome_152"` | Browser TLS + HTTP/2 + header profile |
| `base_url` | `str` | `""` | Base URL prepended to relative request paths |
| `timeout` / `connect_timeout` / `read_timeout` | `float \| None` | `30.0` | Request, connect, and read timeouts in seconds |
| `verify` | `bool \| str` | `True` | `True`, `False`, or path to a custom CA `.pem`/`.der` bundle |
| `cert` | `str \| tuple[str, str]` | `None` | Client mTLS certificate (`combined.pem` or `(crt, key)`) |
| `proxy` / `proxies` / `proxies_pool` | `str \| dict \| list` | `None` | HTTP/HTTPS/SOCKS5 proxy or round-robin proxy list |
| `headers` / `header_order` | `dict \| list[str]` | `None` | Default headers and exact wire header order/casing |
| `params` / `cookies` | `dict` | `None` | Default query parameters and session cookies |
| `auth` | `tuple \| AuthBase` | `None` | `(user, pass)`, `BasicAuth`, `BearerAuth`, or `DigestAuth` |
| `ja3` / `tls_options` / `http2_options` | `str \| dict` | `None` | Custom JA3 string and low-level BoringSSL / H2 overrides |
| `http1_only` / `http2_only` | `bool` | `False` | Force HTTP/1.1 or HTTP/2 transport |
| `resolve` | `dict[str, str \| list]` | `None` | Custom DNS / origin IP mapping (`{"host": "ip"}`) |
| `local_address` / `interface` | `str` | `None` | Bind outbound IPv4/IPv6 address or network interface |
| `system_dns` | `bool` | `False` | Disable built-in Hickory async DNS and use OS resolver |
| `retries` / `retry_backoff` / `retry_statuses` | `int \| float \| tuple` | `0` | Automatic retry count, exponential backoff base, and status codes |
| `retry_on_challenge` / `rotate_impersonate` | `bool` | `False` | Auto-retry and rotate preset/proxy on WAF challenge |
| `storage_state` / `flare_solverr_url` / `solver` | `str \| dict \| callable` | `None` | Playwright `storage_state.json` loader and JS challenge bridge |
| `tls_info` / `keylog_file` / `record_har` | `bool \| str` | `False` | Capture peer cert DER, write Wireshark keylog, record HAR 1.2 |
| `event_hooks` | `dict[str, list]` | `None` | Sync or async `{"request": [...], "response": [...]}` hooks |

### Key `Response` Attributes & Methods

- **Metadata:** `status_code`, `reason`, `reason_phrase`, `url`, `http_version`, `headers`, `cookies`, `elapsed`, `history`, `remote_addr`, `peer_certificate`, `links`, `num_bytes_downloaded`, `challenge`.
- **Status helpers:** `ok`, `is_success`, `is_informational`, `is_redirect`, `is_permanent_redirect`, `has_redirect_location`, `is_client_error`, `is_server_error`, `is_error`, `raise_for_status()`.
- **Body & Streaming:** `content`, `text`, `json()`, `read()`, `aread()`, `acontent()`, `atext()`, `iter_content()`, `iter_bytes()`, `iter_text()`, `iter_lines()`, `aiter_bytes()`, `aiter_content()`, `aiter_text()`, `aiter_lines()`, `close()`, `aclose()`.

### Exceptions (`http_tls.exceptions`)

`RequestException` (`RequestError`, `RequestsError`), `HTTPError` (`HTTPStatusError`), `ConnectionError` (`ConnectError`), `Timeout` (`TimeoutException`), `ConnectTimeout`, `ReadTimeout`, `SSLError`, `TooManyRedirects`, `InvalidURL`.

---

## Testing & Development

```bash
pip install -e ".[test]"
pytest -v tests/
```

Run the live throughput benchmark against `curl_cffi`, `httpx`, and `requests`:

```bash
python benchmarks/bench_vs_competitors.py --url https://www.cloudflare.com/cdn-cgi/trace --n 15 --concurrency 30
```

See [CHANGELOG.md](CHANGELOG.md) for the complete release history.

---

## Hướng dẫn Tiếng Việt

`http_tls` là thư viện HTTP Client viết bằng Rust tích hợp sẵn **BoringSSL** cho Python — giả lập chính xác chữ ký mạng TLS (JA3/JA4) và HTTP/2 (Akamai) của hơn 100 phiên bản trình duyệt thật mà **không cần cài thêm `curl_cffi` hay binary bên ngoài**.

### 1. Cài đặt

```bash
pip install http-tls
```

### 2. Thay thế trực tiếp `requests`, `httpx` và `curl_cffi`

```python
# Giống hệt requests
import http_tls as requests
r = requests.get("https://tls.peet.ws/api/all", impersonate="chrome_149")
print(r.status_code, r.http_version, r.json()["tls"]["ja4"])

# Giống hệt httpx (Client, AsyncClient, base_url, stream, aclose)
import http_tls as httpx
with httpx.Client(base_url="https://httpbin.org", follow_redirects=True) as client:
    r = client.get("/get")
    print(r.is_success, r.reason_phrase)

# Giống hệt curl_cffi
from http_tls import requests, BrowserType
r = requests.get("https://www.apple.com/", impersonate=BrowserType.safari26_4)
```

### 3. Bắn hàng trăm request song song không cần viết `async/await` (`gather`)

```python
import http_tls

with http_tls.Session(impersonate="chrome_149") as s:
    urls = [f"https://httpbin.org/anything?id={i}" for i in range(50)]
    # Thực thi song song trên Rust Tokio (nhả GIL hoàn toàn), giữ đúng thứ tự danh sách
    results = s.gather(urls, concurrency=25)
    print("Hoàn tất:", len(results))
```

### 4. Tải file lớn (Streaming) & Upload file (`files=`)

```python
import http_tls

with http_tls.stream("GET", "https://httpbin.org/bytes/4096") as resp:
    with open("data.bin", "wb") as f:
        for chunk in resp.iter_bytes(chunk_size=1024):
            f.write(chunk)

with http_tls.Session() as s:
    s.post("https://httpbin.org/post", files={"doc": ("note.txt", b"noi-dung", "text/plain")})
```

### 5. Proxy, Xoay Proxy Pool, Ép IP Origin (`resolve`) & Xoay IPv6 (`local_address`)

```python
import http_tls

with http_tls.Session(
    impersonate="chrome_149",
    proxies_pool=[
        "http://user:pass@1.2.3.4:8080",
        "socks5://user:pass@5.6.7.8:1080",
    ],
    retries=3,
    retry_on_challenge=True,
    rotate_impersonate=True,
) as s:
    resp = s.get("https://api.ipify.org?format=json")
    if resp.challenge:
        print("Bị rào chắn JS chặn bởi:", resp.challenge)

# Ép nối thẳng vào IP gốc bỏ qua DNS hệ thống hoặc bind IPv6 /64
with http_tls.Session(
    resolve={"example.com": "93.184.216.34"},
    local_address="2001:db8::1",
) as s:
    resp = s.get("https://example.com/")
```

### 6. Xóa sạch Cookie & Kết hợp Playwright / Camoufox (`storage_state.json`)

```python
import http_tls

# Nạp trực tiếp file storage_state.json xuất từ Playwright/Camoufox (mang theo cf_clearance + User-Agent)
with http_tls.Session(storage_state="state.json", impersonate="firefox_151") as s:
    r = s.get("https://protected-site.example/api")
    s.save_storage_state("state.json")

    # Xóa triệt để cookie ở cả Python lẫn Rust Jar để đổi tài khoản sạch sẽ
    s.cookies.clear()
```

### 7. WebSocket giả lập TLS & Debug gói tin (Wireshark KeyLog + HAR)

```python
import http_tls

with http_tls.Session(
    impersonate="chrome_149",
    keylog_file="sslkeys.log",  # Nạp vào Wireshark để giải mã gói tin HTTPS/HTTP2
    record_har=True,
) as s:
    s.get("https://httpbin.org/get")
    s.export_har("trace.har")   # Kéo thả vào tab Network của Chrome DevTools

    with s.ws_connect("wss://echo.websocket.org") as ws:
        ws.send_text("xin chao")
        print(ws.recv_text())
```

---

## License

Released under the [MIT License](LICENSE).
