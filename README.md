<div align="center">

# 🔐 http_tls

**Rust & BoringSSL TLS (JA3/JA4) and HTTP/2 Impersonating HTTP Client for Python**

[![CI & Release Wheels](https://github.com/real-coder-xD/http_tls/actions/workflows/release.yml/badge.svg)](https://github.com/real-coder-xD/http_tls/actions)
[![PyPI version](https://img.shields.io/pypi/v/http-tls.svg)](https://pypi.org/project/http-tls/)
[![Python versions](https://img.shields.io/badge/python-3.8%20--%203.14-blue.svg)](https://pypi.org/project/http-tls/)
[![Downloads](https://img.shields.io/pypi/dm/http-tls.svg)](https://pypi.org/project/http-tls/)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[Installation](#-installation) • [Quick Start](#-migration--drop-in-quick-start-requests-httpx-curl_cffi-tls-client) • [Benchmarks](#-verified-benchmarks--live-ja4--http2-fingerprint-audit) • [API Reference](#-api-reference-summary) • [FAQ](#-frequently-asked-questions-faq) • [Changelog](CHANGELOG.md)

</div>

`http_tls` (`pip install http-tls`) is a high-performance, standalone **Rust + BoringSSL (`btls`) HTTP client for Python** that reproduces byte-exact **TLS (JA3, JA4, GREASE, ALPS, Post-Quantum `X25519MLKEM768`)** and **HTTP/2 (Akamai)** browser fingerprints for over 100 Chrome, Safari, Firefox, Edge, Opera, OkHttp, and Tor profiles.

Built on Rust PyO3 (`abi3-py38`), Tokio, `wreq`, and Hickory async DNS, `http_tls` ships as a self-contained ~4.3 MB wheel with zero external C or Go dependencies and works as a drop-in replacement for **`requests`**, **`httpx`**, and **`curl_cffi`**.

```bash
pip install http-tls
```

---

## 📌 Key Facts (At a Glance)

| Property | Value |
| :--- | :--- |
| **PyPI Package** | `http-tls` (`pip install http-tls`) |
| **Python Import** | `import http_tls` |
| **TLS / HTTP Engine** | Embedded Rust `wreq` + BoringSSL (`btls`), zero `libcurl` or Go CGo dependency |
| **Async & DNS Stack** | Native Rust Tokio runtime (`pyo3-async-runtimes`) + Hickory async DNS |
| **Drop-in API Compatibility** | `requests`, `httpx` (`Client`, `AsyncClient`, `stream`), and `curl_cffi` (`BrowserType`, `impersonate`) |
| **Sync Parallelism** | `session.gather(urls, concurrency=50)` — GIL-free multi-request batching without `async/await` |
| **Fingerprinting** | 100+ browser presets, custom JA3, `tls_options`, `http2_options`, exact wire `header_order` |
| **WebSockets & Streaming** | TLS-impersonated sync/async WebSockets, sync/async streaming, multipart `files=` |
| **Reverse Engineering & Ops** | Wireshark `SSLKEYLOGFILE` / `keylog_file`, HAR 1.2 export, Playwright `storage_state.json`, WAF `resp.challenge` detector |
| **Python & Platform Support** | Python 3.8 – 3.14+ (ABI3 wheels) on Windows `x86_64`, Linux `manylinux_2_28` (`x86_64`, `aarch64`), macOS (`x86_64`, `arm64`) |
| **License** | MIT |

---

## 📑 Table of Contents

- [Why `http_tls`?](#-why-http_tls)
- [Comparison: `http_tls` vs `curl_cffi`, `primp`, `tls-client`, `httpx`, and `requests`](#-comparison-http_tls-vs-curl_cffi-primp-tls-client-httpx-and-requests)
- [Verified Benchmarks & Live JA4 / HTTP/2 Fingerprint Audit](#-verified-benchmarks--live-ja4--http2-fingerprint-audit)
- [Installation](#-installation)
- [Migration & Drop-in Quick Start (`requests`, `httpx`, `curl_cffi`, `tls-client`)](#-migration--drop-in-quick-start-requests-httpx-curl_cffi-tls-client)
- [High-Concurrency Execution: Native Tokio Async & Sync `gather()`](#-high-concurrency-execution-native-tokio-async--sync-gather)
- [Streaming Responses & Multipart File Uploads](#-streaming-responses--multipart-file-uploads)
- [TLS-Impersonated WebSockets (Sync & Async)](#-tls-impersonated-websockets-sync--async)
- [Custom JA3, BoringSSL `tls_options`, HTTP/2 Settings & Wire Header Order](#-custom-ja3-boringssl-tls_options-http2-settings--wire-header-order)
- [Proxies, Custom DNS (`resolve`), IPv6 `/64` Binding & Hickory DNS](#-proxies-custom-dns-resolve-ipv6-64-binding--hickory-dns)
- [Authentication (`Basic`, `Bearer`, `Digest`), Custom CA Bundles & Mutual TLS (mTLS)](#-authentication-basic-bearer-digest-custom-ca-bundles--mutual-tls-mtls)
- [WAF Challenge Detection, Retries, Playwright `storage_state.json` & Solver Bridge](#-waf-challenge-detection-retries-playwright-storage_statejson--solver-bridge)
- [Traffic Inspection: Wireshark KeyLog & HAR 1.2 Export](#-traffic-inspection-wireshark-keylog--har-12-export)
- [Supported Browser Impersonation Presets (100+ Profiles)](#-supported-browser-impersonation-presets-100-profiles)
- [API Reference Summary](#-api-reference-summary)
- [Frequently Asked Questions (FAQ)](#-frequently-asked-questions-faq)
- [Testing & Development](#-testing--development)
- [License](#-license)

---

## 💡 Why `http_tls`?

Standard Python HTTP clients (`requests`, `urllib3`, `aiohttp`, `httpx`) rely on the system OpenSSL stack. Their TLS `ClientHello` cipher suites, extensions, elliptic curves, and HTTP/2 `SETTINGS` frames produce non-browser JA3/JA4 signatures that are immediately flagged or throttled by Cloudflare, Akamai, DataDome, PerimeterX, Imperva, and Fastly.

Existing Python TLS-impersonating alternatives each carry architectural trade-offs:
- `tls-client` wraps a Go CGo shared library (`utls`), which suffers from CGo memory leaks in long-running workers, lacks native `asyncio`, and does not synchronize `cookies.clear()` across the FFI boundary.
- `curl_cffi` binds `libcurl-impersonate` over CFFI, carrying C memory-management complexity and lacking synchronous Rust-native batching, built-in WAF interstitial detection, HAR recording, or Playwright `storage_state.json` integration.
- `primp` and `rnet` expose Rust engines but do not provide full drop-in API compatibility with `requests`, `httpx`, and `curl_cffi`.

`http_tls` solves these problems in a single compiled Rust PyO3 module:
1. **Byte-Exact BoringSSL Fingerprinting:** Authentic JA3, JA4, GREASE, ALPS, Post-Quantum `X25519MLKEM768`, and Akamai HTTP/2 frame order for Chrome, Safari, Firefox, Edge, Opera, OkHttp, and Tor.
2. **True Native Async + GIL-Free Sync Batching:** `AsyncSession` maps Rust Tokio futures directly onto Python's `asyncio` event loop with zero `asyncio.to_thread` overhead. Synchronous code can call `session.gather(urls, concurrency=50)` to execute batches concurrently inside Rust while releasing the GIL.
3. **Triple Drop-in API:** Switch from `requests`, `httpx`, or `curl_cffi` by changing a single import line.
4. **Rust RAII Memory Safety:** Shared process-wide Tokio runtime and automatic resource cleanup with minimal Python heap overhead (16.4 KB peak Python allocation in sequential tests).

---

## 🆚 Comparison: `http_tls` vs `curl_cffi`, `primp`, `tls-client`, `httpx`, and `requests`

✅ Supported &nbsp;&nbsp; 🟡 Partial &nbsp;&nbsp; ❌ Not supported

| Capability | `http_tls` | `curl_cffi` | `primp` / `rnet` | `tls-client` | `httpx` | `requests` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Standalone BoringSSL TLS / JA4 | ✅ 100+ presets | ✅ | ✅ | 🟡 Go `utls` | ❌ | ❌ |
| Custom JA3, TLS & H2 Options | ✅ | ✅ | 🟡 | ✅ | ❌ | ❌ |
| Exact Wire Header Order (`OrigHeaderMap`) | ✅ | 🟡 | ✅ | ✅ | ❌ | ❌ |
| Native Event-Loop Async | ✅ Tokio | ✅ libcurl | ✅ Tokio | ❌ | ✅ | ❌ |
| Sync Parallel `gather()` (No `async/await`) | ✅ Rust Tokio | ❌ | ❌ | ❌ | ❌ | ❌ |
| `requests` + `httpx` + `curl_cffi` Drop-in | ✅ | 🟡 | ❌ | ❌ | 🟡 `httpx` only | 🟡 `requests` only |
| Async Hickory DNS & Custom `resolve` | ✅ | 🟡 `resolve` only | 🟡 | ❌ | ❌ | ❌ |
| Outbound IPv4 / IPv6 `/64` Socket Binding | ✅ | ✅ | 🟡 | ❌ | 🟡 | ❌ |
| TLS-Impersonated WebSockets (Sync & Async) | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Streaming, Multipart, Custom CA, mTLS | ✅ | ✅ | 🟡 | 🟡 | ✅ | ✅ |
| RFC 7616 `DigestAuth` (MD5/SHA-256/512) | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Deep `cookies.clear()` Sync Across FFI | ✅ | ✅ | ✅ | ❌ Broken | ✅ | ✅ |
| Built-in WAF `resp.challenge` Detector | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Playwright `storage_state.json` & Solver Bridge | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Wireshark `keylog_file` & HAR 1.2 Export | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Memory Safety (No CGo / Manual Free) | ✅ Rust RAII | 🟡 C/CFFI | ✅ Rust RAII | ❌ Go CGo leaks | ✅ Python | ✅ Python |

---

## 📊 Verified Benchmarks & Live JA4 / HTTP/2 Fingerprint Audit

### 1. Live Multi-Browser Fingerprint Audit (`https://tls.peet.ws/api/all`)

Measured directly using the standalone Rust BoringSSL engine (`engine="rust"`, zero external dependencies):

| Browser Preset | Negotiated Protocol | JA4 Fingerprint | Akamai HTTP/2 Fingerprint |
| :--- | :--- | :--- | :--- |
| `chrome_149` | HTTP/2 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `edge_148` | HTTP/2 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `safari_26_4` | HTTP/2 | `t13d2014h2_a09f3c656075_e42f34c56612` | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` |
| `firefox_151` | HTTP/2 | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` |
| `opera_131` | HTTP/2 | `t13d1516h2_8daaf6152771_02713d6af862` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `okhttp_5` | HTTP/2 | `t13d1613h2_46e7e9700bed_eca864cca44a` | `4:16777216\|16711681\|0\|m,p,a,s` |

### 2. Throughput, Latency & Python Heap Usage (`https://www.cloudflare.com/cdn-cgi/trace`)

Reproduce locally with `python benchmarks/bench_vs_competitors.py`:

**Sequential Synchronous Benchmark (15 requests, warm connection):**

| Python HTTP Client | Median Latency | Throughput | Peak Python Memory (`tracemalloc`) |
| :--- | ---: | ---: | ---: |
| `http_tls` (Rust BoringSSL) | 38.0 ms | 24.4 req/s | 16.4 KB |
| `curl_cffi` | 47.2 ms | 10.4 req/s | 19.2 KB |
| `httpx` (HTTP/2, no TLS impersonation) | 40.0 ms | 15.7 req/s | 249.3 KB |
| `requests` (HTTP/1.1) | 46.6 ms | 22.1 req/s | 170.7 KB |

**Concurrent Asynchronous Benchmark (30 simultaneous requests):**

| Python Async HTTP Client | Average per Request | Throughput | Peak Python Memory (`tracemalloc`) |
| :--- | ---: | ---: | ---: |
| `http_tls.AsyncSession` (Native Tokio) | 2.9 ms | 346.0 req/s | 200.0 KB |
| `curl_cffi.AsyncSession` | 4.7 ms | 211.4 req/s | 234.6 KB |
| `httpx.AsyncClient` | 6.5 ms | 153.0 req/s | 525.0 KB |

In concurrent workloads, `http_tls` delivers **1.64x higher throughput than `curl_cffi`** and **2.26x higher throughput than `httpx`** while allocating **62% less Python heap memory than `httpx`**.

---

## 📦 Installation

Prebuilt ABI3 wheels (~4.3 MB) are published on PyPI for Windows (`x86_64`), Linux (`manylinux_2_28` `x86_64` and `aarch64`), and macOS (`x86_64` and `arm64`), supporting Python 3.8 through 3.14+:

```bash
pip install http-tls
```

Upgrade to the latest version:

```bash
pip install -U http-tls
```

### Building from Source

Building from source requires Rust (`>= 1.98`), `cmake`, `perl`, `clang`/`libclang` (plus `nasm` on Windows):

```bash
git clone https://github.com/real-coder-xD/http_tls.git
cd http_tls
pip install maturin
maturin build --release --out dist
pip install dist/*.whl
```

---

## 🚀 Migration & Drop-in Quick Start (`requests`, `httpx`, `curl_cffi`, `tls-client`)

### 1. Drop-in Replacement for `requests`

Replace `import requests` with `import http_tls as requests`:

```python
import http_tls as requests

resp = requests.get("https://httpbin.org/get", timeout=10)
resp.raise_for_status()

print(resp.status_code == requests.codes.ok)  # True
print(bool(resp.ok), resp.reason)             # True OK
print(resp.headers["content-type"])           # Case-insensitive header access

with requests.session(params={"format": "json"}) as s:
    s.get("https://httpbin.org/cookies/set?token=abc")
    print(s.cookies.get_dict())               # {'token': 'abc'}

    # Deep-clear removes cookies from both the Python wrapper and the Rust cookie jar
    s.cookies.clear()
    print(s.get("https://httpbin.org/cookies").json()["cookies"])  # {}
```

### 2. Drop-in Replacement for `httpx`

Replace `import httpx` with `import http_tls as httpx`:

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

### 3. Drop-in Replacement for `curl_cffi`

Replace `from curl_cffi import requests, BrowserType` with `from http_tls import requests, BrowserType`:

```python
from http_tls import requests, BrowserType

resp = requests.get(
    "https://tls.peet.ws/api/all",
    impersonate=BrowserType.chrome149,
)
print(resp.status_code, resp.json()["tls"]["ja4"])
```

### 4. Migrating from `tls-client`

Replace `tls_client.Session(client_identifier="chrome_120", random_tls_extension_order=True)` with `http_tls.Session(impersonate="chrome_149")`:

```python
import http_tls

with http_tls.Session(impersonate="chrome_149") as session:
    resp = session.get("https://tls.peet.ws/api/all")
    print(resp.status_code, resp.http_version)
```

---

## ⚡ High-Concurrency Execution: Native Tokio Async & Sync `gather()`

### Native Tokio Async (`AsyncSession` / `AsyncClient`)

`AsyncSession` awaits Rust Tokio futures directly on Python's `asyncio` loop without spawning Python worker threads:

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

`session.gather()` dispatches a list of URLs or request dictionaries directly onto the Rust Tokio multi-thread runtime while releasing the GIL, returning `List[Response]` in the exact input order:

```python
import http_tls

with http_tls.Session(base_url="https://httpbin.org", impersonate="chrome_149") as s:
    # Plain URL list
    responses = s.gather([f"/anything?i={i}" for i in range(50)], concurrency=25)

    # Mixed HTTP methods, headers, and JSON payloads
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

## 📥 Streaming Responses & Multipart File Uploads

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

### Multipart Form-Data Uploads (`files=`)

```python
import http_tls

with http_tls.Session() as s:
    resp = s.post(
        "https://httpbin.org/post",
        data={"description": "quarterly-report"},
        files={
            "file": ("report.txt", b"payload-bytes", "text/plain"),
        },
    )
    print(resp.status_code)
```

---

## 🔌 TLS-Impersonated WebSockets (Sync & Async)

Both synchronous and native async WebSocket connections inherit the session's BoringSSL TLS fingerprint, proxy settings, cookies, and custom headers:

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

## 🧬 Custom JA3, BoringSSL `tls_options`, HTTP/2 Settings & Wire Header Order

For custom mobile clients, non-standard APIs, or fingerprint research, override TLS parameters, HTTP/2 settings, and exact wire header casing and ordering (`OrigHeaderMap`):

```python
import http_tls

with http_tls.Session(
    # Standard 5-field JA3 string
    ja3="771,4865-4866-4867-49195-49199,0-23-65281,29-23-24,0",
    # Fine-grained BoringSSL configuration
    tls_options={
        "alpn": ["h2", "http/1.1"],
        "grease_enabled": True,
        "permute_extensions": True,
        "enable_ech_grease": True,
        "enable_ocsp_stapling": True,
    },
    # Custom HTTP/2 SETTINGS frame parameters
    http2_options={
        "header_table_size": 65536,
        "enable_push": False,
        "initial_window_size": 6291456,
        "max_header_list_size": 262144,
    },
    # Enforce exact wire header order and casing
    header_order=["Host", "Connection", "User-Agent", "Accept", "Accept-Language"],
    # Optional protocol forcing: http1_only=True or http2_only=True
) as s:
    resp = s.get("https://tls.peet.ws/api/all")
```

---

## 🌐 Proxies, Custom DNS (`resolve`), IPv6 `/64` Binding & Hickory DNS

`http_tls` uses **Hickory async DNS** by default (eliminating OS resolver thread contention), supports HTTP/HTTPS/SOCKS5 proxies with round-robin pools, overrides DNS resolution per hostname without breaking TLS SNI, and binds outbound IPv4/IPv6 addresses for proxy-less IPv6 `/64` rotation:

```python
import http_tls

# Single HTTP / HTTPS / SOCKS5 proxy
r = http_tls.get("https://api.ipify.org?format=json", proxy="socks5://user:pass@1.2.3.4:1080")

# Custom DNS / Origin IP override (keeps TLS SNI and Host header intact)
with http_tls.Session(
    resolve={"api.example.com": "93.184.216.34"},
    # Bind outbound source IP (ideal for rotating an IPv6 /64 subnet without proxies)
    local_address="2001:db8::42",
    # On Linux/macOS: interface="eth0"
    # Pass system_dns=True to fall back to the OS DNS resolver instead of Hickory DNS
) as s:
    r = s.get("https://api.example.com/health")
    print("Connected peer:", r.remote_addr)
```

---

## 🔑 Authentication (`Basic`, `Bearer`, `Digest`), Custom CA Bundles & Mutual TLS (mTLS)

```python
import http_tls
from http_tls import BasicAuth, BearerAuth, DigestAuth

# Basic, Bearer, and RFC 7616 Digest Auth (MD5, SHA-256, SHA-512 — sync & async)
with http_tls.Session(auth=DigestAuth("alice", "secret")) as s:
    r = s.get("https://httpbin.org/digest-auth/auth/alice/secret/SHA-256")

# Custom Root CA bundle (corporate TLS proxy or self-signed CA) + peer cert inspection
with http_tls.Session(verify="/path/to/custom_ca_bundle.pem", tls_info=True) as s:
    r = s.get("https://internal.corp.local")
    print("Server leaf certificate DER length:", len(r.peer_certificate or b""))

# Mutual TLS (client certificate + PKCS#8 private key, or single combined PEM)
with http_tls.Session(cert=("client.crt", "client.key")) as s:
    r = s.get("https://mtls.example.com")
```

---

## 🧱 WAF Challenge Detection, Retries, Playwright `storage_state.json` & Solver Bridge

### 1. Automatic Anti-Bot Interstitial Detection & Resilient Retries

`resp.challenge` inspects status codes, headers, and challenge payloads to detect interstitials from `cloudflare`, `ddos-guard`, `datadome`, `perimeterx`, `imperva`, `sucuri`, `vercel`, and `akamai`:

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
        print("Challenge provider detected:", resp.challenge)
```

### 2. Playwright / Camoufox `storage_state.json` & Solver Bridge

Reuse clearance sessions (`cf_clearance`, session cookies, and `User-Agent`) exported by Playwright or Camoufox, or attach FlareSolverr / a custom browser solver callback:

```python
import http_tls

# Load cookies + User-Agent from Playwright context.storage_state(path="state.json")
with http_tls.Session(storage_state="state.json", impersonate="firefox_151") as s:
    resp = s.get("https://protected.example.com/api/data")
    s.save_storage_state("state.json")

# Automatic FlareSolverr or custom solver callback when a JS challenge is returned
with http_tls.Session(
    retries=1,
    retry_on_challenge=True,
    flare_solverr_url="http://localhost:8191/v1",
) as s:
    resp = s.get("https://protected.example.com")
```

### 3. Request & Response Event Hooks

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

## 🔍 Traffic Inspection: Wireshark KeyLog & HAR 1.2 Export

Inspect TLS-encrypted HTTP/2 frames in Wireshark or replay full request/response waterfalls in Chrome DevTools:

```python
import http_tls

with http_tls.Session(
    impersonate="chrome_149",
    keylog_file="sslkeys.log",  # Or set SSLKEYLOGFILE env var to decrypt TLS in Wireshark
    record_har=True,            # Record all HTTP transactions in HAR 1.2 format
) as s:
    s.get("https://httpbin.org/get")
    s.post("https://httpbin.org/post", json={"test": 1})
    s.export_har("session_trace.har")  # Drag-and-drop into Chrome DevTools Network tab
```

---

## 🧩 Supported Browser Impersonation Presets (100+ Profiles)

Query the full list programmatically with `http_tls.supported_presets()`:

- **Google Chrome (`chrome_100` – `chrome_152`):** Desktop Windows/Linux, macOS (`chrome_152_macos`, `chrome_151_macos`), Android (`chrome_131_android`), and dynamic forward-version Client Hints patching.
- **Microsoft Edge (`edge_101` – `edge_152`):** `edge_152`, `edge_148`, `edge_147`, `edge_145`, `edge_142`, `edge_134`, `edge_131`, `edge_127`, `edge_122`, `edge_101`.
- **Apple Safari (`safari_15_3` – `safari_27`):** macOS (`safari_27`, `safari_26_4`, `safari_18_5`, `safari_18`, `safari_17`), iOS (`safari_ios_26_2`, `safari_ios_26`, `safari_ios_18_1_1`), and iPadOS (`safari_ipad_26`, `safari_ipad_18`).
- **Mozilla Firefox (`firefox_109` – `firefox_155`):** Desktop, private browsing (`firefox_private_136`), and Android (`firefox_android_135`).
- **Opera (`opera_116` – `opera_131`):** `opera_131`, `opera_130`, `opera_128`, `opera_124`, `opera_120`, `opera_116`.
- **OkHttp (Android):** `okhttp_5`, `okhttp_4_12`, `okhttp_4_10`, `okhttp_4_9`, `okhttp_3_14`, `okhttp_3_11`.
- **Tor & Automatic Rotation:** `tor_14_5`, `random`, and `weighted_random` (market-share weighted browser + OS selection).

---

## 📘 API Reference Summary

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
- **Status Helpers:** `ok`, `is_success`, `is_informational`, `is_redirect`, `is_permanent_redirect`, `has_redirect_location`, `is_client_error`, `is_server_error`, `is_error`, `raise_for_status()`.
- **Body & Streaming:** `content`, `text`, `json()`, `read()`, `aread()`, `acontent()`, `atext()`, `iter_content()`, `iter_bytes()`, `iter_text()`, `iter_lines()`, `aiter_bytes()`, `aiter_content()`, `aiter_text()`, `aiter_lines()`, `close()`, `aclose()`.

### Exception Hierarchy (`http_tls.exceptions`)

Compatible with `requests`, `httpx`, and `curl_cffi` exception names:

`RequestException` (`RequestError`, `RequestsError`), `HTTPError` (`HTTPStatusError`), `ConnectionError` (`ConnectError`), `Timeout` (`TimeoutException`), `ConnectTimeout`, `ReadTimeout`, `SSLError`, `TooManyRedirects`, `InvalidURL`.

---

## ❓ Frequently Asked Questions (FAQ)

### How does `http_tls` differ from `curl_cffi`?
`http_tls` is compiled in Rust against BoringSSL (`btls`) and Tokio rather than wrapping `libcurl` via CFFI. In live benchmarks against Cloudflare, `http_tls` achieves higher sync and async throughput (346 req/s vs 211 req/s at 30-way concurrency), adds GIL-free parallel `session.gather()` for synchronous code, and includes built-in WAF challenge detection, RFC 7616 Digest Auth, HAR 1.2 export, Wireshark `keylog_file`, and Playwright `storage_state.json` support.

### Does `http_tls` require `libcurl`, Go, or external binaries?
No. BoringSSL, Tokio, HTTP/2, and Hickory DNS are compiled directly into the native PyO3 extension inside the ~4.3 MB wheel. Installing via `pip install http-tls` requires zero external runtime dependencies.

### How can I send concurrent requests in `http_tls` without writing `async/await`?
Use `session.gather(urls, concurrency=50)`. It executes all requests in parallel on the Rust Tokio multi-thread runtime while releasing Python's GIL and returns responses in the exact input order.

### How do I reuse Playwright or Camoufox clearance cookies in `http_tls`?
Export browser cookies with `context.storage_state(path="state.json")` and pass `storage_state="state.json"` to `http_tls.Session(...)`. `http_tls` loads all matching cookies and User-Agent headers into the Rust cookie jar and can write updated cookies back with `session.save_storage_state("state.json")`.

### How do I decrypt and inspect `http_tls` HTTPS / HTTP/2 traffic in Wireshark?
Pass `keylog_file="sslkeys.log"` to `Session(...)` (or set the `SSLKEYLOGFILE` environment variable), then point Wireshark's `Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename` to that file.

### Which Python versions and operating systems are supported?
`http_tls` publishes prebuilt ABI3 wheels (`cp38-abi3`) covering Python 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, and 3.14+ on Windows (`x86_64`), Linux (`manylinux_2_28` `x86_64` and `aarch64`), and macOS (`x86_64` and Apple Silicon `arm64`).

---

## 🧪 Testing & Development

Run the full pytest suite (23 integration and unit tests covering TLS/JA4, HTTP/2, sync/async streaming, `gather()`, WebSockets, Digest Auth, custom CA/mTLS, `storage_state.json`, HAR export, and `httpx`/`requests` parity):

```bash
pip install -e ".[test]"
pytest -v tests/
```

Run the live throughput and memory benchmark against `curl_cffi`, `httpx`, and `requests`:

```bash
python benchmarks/bench_vs_competitors.py --url https://www.cloudflare.com/cdn-cgi/trace --n 15 --concurrency 30
```

See [CHANGELOG.md](CHANGELOG.md) for the complete version history.

---

## 📄 License

Released under the [MIT License](LICENSE).
