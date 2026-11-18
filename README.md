<div align="center">

# ⚡ http_tls

**High-performance Rust-powered HTTP client with byte-exact TLS (JA3/JA4) & HTTP/2 fingerprint impersonation.**  
*100% Drop-in replacement for both `requests` and `curl_cffi`.*

[![CI & Release Wheels](https://github.com/real-coder-xD/http_tls/actions/workflows/release.yml/badge.svg)](https://github.com/real-coder-xD/http_tls/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue?logo=python)](https://pypi.org/project/http-tls/)
[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-orange?logo=rust)](https://www.rust-lang.org/)
[![Fingerprint](https://img.shields.io/badge/TLS%20Fingerprint-JA3%20%2F%20JA4%20%2F%20H2-green)](#benchmarks--fingerprint-parity)

[English](README.md) • [Tiếng Việt](#hướng-dẫn-tiếng-việt)

</div>

---

## 🌟 Why http_tls?

Traditional HTTP libraries (`requests`, `urllib3`, `aiohttp`, `httpx`) are blocked instantly by modern anti-bot systems (**Cloudflare Bot Management, Akamai, DataDome, CloudFront**) because their TLS ClientHello (JA3/JA4) and HTTP/2 settings frames leak signatures.

`curl_cffi` solved this by wrapping C-based `curl-impersonate`, but suffers from complex C runtime dependencies, memory leak risks in long-running async loops, and difficult cross-compilation.

**`http_tls` is engineered in Rust to give you the best of both worlds:**
1. **Byte-Exact TLS & HTTP/2 Fingerprint:** Generates identical JA4 hashes (`t13d1517h2_...`) and Chrome HTTP/2 pseudo-header ordering (`:method`, `:authority`, `:scheme`, `:path` -> `m,a,s,p`).
2. **100% Drop-in for `requests`:** Replace `import requests` with `import http_tls as requests` — zero code changes required.
3. **100% Drop-in for `curl_cffi`:** Fully compatible with `from http_tls import requests, BrowserType`.
4. **Blazing Fast (+32% Throughput):** Multi-threaded Rust core with complete Python GIL release (`py.allow_threads`).
5. **Modern 2026 Presets:** Ships with presets up to Chrome 152, Safari 27, Firefox 155, and Edge 152, plus dynamic version generation.
6. **Self-Contained & Stable ABI3:** Single wheel distribution for all Python versions (3.8 - 3.14+).

---

## 📊 Benchmarks & Fingerprint Parity

Tested against `https://tls.peet.ws/api/all` (the canonical TLS fingerprint diagnostic tool):

| Metric | `requests` / `httpx` | `curl_cffi` (pip) | `http_tls` (Rust) | Cloudflare Status |
| :--- | :---: | :---: | :---: | :---: |
| **JA4 TLS Hash** | `t13d1011h2` (Bot) | `t13d1517h2` (Chrome) | **`t13d1517h2` (Chrome)** | ✅ **PASSED** |
| **H2 Pseudo-Headers** | `m,s,a,p` (Bot) | `m,a,s,p` (Chrome) | **`m,a,s,p` (Chrome)** | ✅ **PASSED** |
| **H2 Akamai Settings** | Mismatched | Browser-exact | **Browser-exact** | ✅ **PASSED** |
| **Throughput (10 reqs)**| ~520 ms/req | ~437 ms/req | **~296 ms/req (32% faster)**| ⚡ **FASTEST** |
| **Memory Safety** | Python Managed | C Pointers (Manual) | **Rust RAII (Safe)** | 🛡️ **SAFE** |

### 🏆 Complete Feature Comparison Matrix

| Feature | **`http_tls`** | `requests` | `httpx` | `curl_cffi` | `tls-client` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **TLS Fingerprinting** | ✅ **50+ (Chrome 152)** | ❌ | ❌ | ✅ | ✅ |
| **Async Support** | ✅ **Native Tokio (No GIL)** | ❌ | ✅ | ✅ | ❌ |
| **HTTP/2 Fingerprint** | ✅ **`m,a,s,p` + Frames** | ❌ | ✅ | ✅ | ✅ |
| **`httpx`-like API** | ✅ **`Client` / `AsyncClient`** | ❌ | ✅ | ❌ | ❌ |
| **Cookie `clear()` Works** | ✅ **Deep Sync (Core + Memory)**| ✅ | ✅ | ✅ | ❌ |
| **No Memory Leaks** | ✅ **Rust RAII (Zero GC Lag)** | ✅ | ✅ | ✅ | ❌ |
| **Auto-download Binary** | ✅ **Prebuilt ABI3 Wheels** | N/A | N/A | ✅ | ❌ |

---

## 🚀 Quick Start

### Installation

```bash
pip install http-tls
```

*Or build from source via Maturin:*
```bash
git clone https://github.com/real-coder-xD/http_tls.git
cd http_tls
pip install maturin
maturin build --release
pip install ./target/wheels/*.whl
```

---

### Mode 1: 100% Drop-in for `requests`

Simply swap your import. All existing code, sessions, headers, and exception handling work seamlessly:

```python
import http_tls as requests

# GET request with automatic Chrome 152 impersonation
resp = requests.get("https://httpbin.org/get", timeout=10)
resp.raise_for_status()

# Standard requests properties
print(resp.status_code == requests.codes.ok) # True
print(resp.ok)                                # True
print(resp.headers["content-type"])          # Case-insensitive headers!

# Session with cookie persistence and custom headers
with requests.Session() as s:
    s.headers.update({"Authorization": "Bearer secret_token"})
    s.get("https://httpbin.org/cookies/set?user=dev")
    
    r = s.get("https://httpbin.org/cookies")
    print(r.json()["cookies"])  # {'user': 'dev'}
```

---

### Mode 2: 100% Drop-in for `curl_cffi`

If your project currently imports `curl_cffi`:

```python
from http_tls import requests
from http_tls import BrowserType

# Use BrowserType enum or string presets
resp = requests.get(
    "https://www.upwork.com",
    impersonate=BrowserType.chrome152,
    proxies={"all": "http://user:pass@proxy.example.com:8080"}
)
print("Status:", resp.status_code)
print("CF-Ray:", resp.headers.get("cf-ray"))
```

---

### Mode 3: 100% Drop-in for `httpx`

Use standard `httpx` conventions (`Client`, `AsyncClient`, `follow_redirects`, `resp.is_success`, `resp.read()`):

```python
import http_tls as httpx

with httpx.Client(follow_redirects=True, impersonate="chrome_152") as client:
    resp = client.get("https://httpbin.org/get")
    print("Success:", resp.is_success)  # True
    print("Content bytes:", len(resp.read()))

# Async Client
import asyncio

async def fetch():
    async with httpx.AsyncClient(follow_redirects=True) as client:
        r = await client.get("https://httpbin.org/status/200")
        print("Async Status:", r.status_code, "| is_success:", r.is_success)

asyncio.run(fetch())
```

---

### Mode 4: Native High-Performance Async (`asyncio`)

Crawl hundreds of protected endpoints concurrently:

```python
import asyncio
import http_tls

async def worker(session, index):
    url = f"https://httpbin.org/anything?idx={index}"
    resp = await session.get(url)
    return resp.json()["args"]

async def main():
    async with http_tls.AsyncSession(impersonate="chrome_152") as session:
        tasks = [worker(session, i) for i in range(20)]
        results = await asyncio.gather(*tasks)
        print(f"Fetched {len(results)} items successfully!")

asyncio.run(main())
```

---

## 🎛️ Dual-Engine Architecture

`http_tls` gives you explicit control over the network engine:

```python
import http_tls

# Engine 1: 'impersonate' (Default / Auto)
# 100% byte-exact TLS & H2 frames to bypass Cloudflare Bot Management & Akamai.
with http_tls.Session(impersonate="chrome_152", engine="impersonate") as s:
    resp = s.get("https://www.upwork.com")

# Engine 2: 'rust'
# Pure Rust Tokio + Rustls runtime. Maximum memory safety and zero external C dependencies.
with http_tls.Session(impersonate="chrome_152", engine="rust") as s:
    resp = s.get("https://httpbin.org/get")
```

---

### Mode 5: Streaming Large Responses (`stream=True`)

Stream large payloads, downloads, and EventStreams directly from the socket without loading entire bodies into RAM:

```python
import http_tls as requests

# Stream download chunk-by-chunk
with requests.get("https://httpbin.org/stream/20", stream=True) as resp:
    for line in resp.iter_lines():
        if line:
            print("Received line:", line.decode("utf-8"))

# Custom chunk size
with requests.get("https://example.com/large-file.zip", stream=True) as resp:
    with open("local_file.zip", "wb") as f:
        for chunk in resp.iter_content(chunk_size=65536):
            f.write(chunk)
```

---

### Mode 6: Built-in Anti-Bot & JS Challenge Detection

Inspect whether an anti-bot system is challenging your request (`resp.challenge` returns the provider name or `None`):

```python
import http_tls as requests

resp = requests.get("https://protected-site.com", impersonate="chrome_152")

if resp.challenge:
    print(f"Intercepted by: {resp.challenge}")
    # Detected providers: "cloudflare", "datadome", "ddos-guard", "imperva", "perimeterx", "sucuri"
else:
    print("Normal response:", resp.status_code)
```

---

### Mode 7: Custom CA Bundles & Client Certificates (mTLS)

```python
import http_tls as requests

# Custom Root CA bundle (PEM)
session = requests.Session(verify="./custom_ca_bundle.pem")

# Client mTLS authentication
session = requests.Session(cert=("client.crt", "client.key"))
# Or combined PEM:
session = requests.Session(cert="client_combined.pem")
```

---

### Mode 8: True Session Cookie Reset (`session.cookies.clear()`)

Unlike other libraries where clearing cookies leaves underlying session engine cookies intact, `http_tls` performs deep synchronization, wiping cookies from both Python memory and the native Rust/C core:

```python
import http_tls as requests

session = requests.Session()
session.get("https://site.com/login")  # Sets session cookies

# Deep-clear: resets cookies across Python dict, libcurl, and Rust Tokio Jar
session.cookies.clear()  # or session.clear_cookies()

# Subsequent requests will be sent as a completely clean, anonymous session
resp = session.get("https://site.com/profile")
```

---

## 🎯 Supported Browser Presets (Updated to Nov 2026)

- **Chrome (Default `chrome_152`):** `chrome_152`, `chrome_152_macos`, `chrome_151`, `chrome_150`, `chrome_146`, `chrome_145`, `chrome_142`, `chrome_136`, `chrome_133`, `chrome_131`, `chrome_130`, `chrome_128`, `chrome_124`
- **Dynamic Generator:** You can pass any `chrome_{N}` version (e.g. `chrome_135`), and `http_tls` will automatically calculate GREASE ciphers, Client Hints, and Sec-CH-UA.
- **Edge:** `edge_152`, `edge_142`, `edge_131`, `edge_128`, `edge_124`
- **Safari:** `safari_27`, `safari_26`, `safari_18_4`, `safari_18`, `safari_17`
- **Firefox:** `firefox_155`, `firefox_154`, `firefox_153`, `firefox_147`, `firefox_144`, `firefox_135`, `firefox_133`, `firefox_130`
- **Tor:** `tor_14_5`

---

## 🛡️ Cloudflare & WAF Bypass Cheat Sheet

1. **Cloudflare CDN / Basic WAF:** Passes automatically with 200 OK.
2. **Cloudflare Bot Management (Super Bot Fight Mode):** `http_tls` matches Chrome's JA4 and HTTP/2 settings, preventing 403 blocks.
3. **Turnstile / Managed Challenge ("Just a moment..."):**
   - **Recommended:** Pair `http_tls` with clean **Residential Proxies** so Cloudflare skips the challenge.
   - **Alternative:** Solve Turnstile once via headless browser (`playwright`/`nodriver`) and pass the `cf_clearance` cookie into `http_tls.Session(cookies={"cf_clearance": "..."})`.

---

<details id="hướng-dẫn-tiếng-việt">
<summary><b>🇻🇳 Xem hướng dẫn chi tiết bằng Tiếng Việt (Click để mở)</b></summary>

### Hướng dẫn Tiếng Việt

`http_tls` là thư viện HTTP Client viết bằng Rust cho Python, thiết kế để thay thế hoàn hảo cho cả `requests` và `curl_cffi`:

1. **Thay thế `requests`:**
   ```python
   import http_tls as requests
   resp = requests.get("https://httpbin.org/get")
   print(resp.json())
   ```
2. **Thay thế `curl_cffi`:**
   ```python
   from http_tls import requests, BrowserType
   resp = requests.get("https://target.com", impersonate=BrowserType.chrome152)
   ```
3. **Thay thế `httpx` (Hỗ trợ Async & Client):**
   ```python
   import http_tls as httpx
   with httpx.Client(follow_redirects=True) as client:
       resp = client.get("https://httpbin.org/get")
       print(resp.is_success, resp.status_code)
   ```
4. **Tải file lớn tiết kiệm RAM (Streaming):**
   ```python
   import http_tls as requests
   with requests.get("https://httpbin.org/stream/10", stream=True) as resp:
       for line in resp.iter_lines():
           if line:
               print(line.decode("utf-8"))
   ```
5. **Tự động nhận diện rào chắn Anti-Bot:**
   ```python
   import http_tls as requests
   resp = requests.get("https://target.com", impersonate="chrome_152")
   if resp.challenge:
       print("Bị chặn bởi:", resp.challenge)  # 'cloudflare', 'datadome', 'ddos-guard'...
   ```
6. **Xóa sạch phiên và Cookie (Deep Clear):**
   ```python
   session = requests.Session()
   session.cookies.clear()  # Xóa sạch cả Python dict lẫn session ngầm của Rust và libcurl
   ```
7. **Cào dữ liệu Async đa luồng:**
   ```python
   import asyncio, http_tls
   async def main():
       async with http_tls.AsyncSession(impersonate="chrome_152") as s:
           r = await s.get("https://httpbin.org/get")
           print(r.status_code)
   asyncio.run(main())
   ```

</details>

---

## 📄 License

Released under the [MIT License](LICENSE).
