<div align="center">

# `http_tls`

**Rust & Pure BoringSSL TLS (JA3/JA4), HTTP/2 & UDP QUIC HTTP/3 Impersonating HTTP Client for Python**

*Byte-exact browser fingerprints across HTTP/1.1, HTTP/2, and pure BoringSSL UDP QUIC HTTP/3 (**Real ECH `sni=encrypted` on both TCP H2 & UDP H3**, Post-Quantum `X25519MLKEM768`, **HTTP/3 over SOCKS5 UDP Associate**, **Session-Wide DoH**), a **100% Pure Rust HTML5 CSS3 / XPath 1.0 / JSON Path / DFA Regex extraction engine**, native Tokio async, and GIL-free parallel batching — a drop-in replacement for `requests`, `httpx`, and `curl_cffi` shipped as one self-contained ABI3 wheel with zero Python dependencies.*

[![PyPI version](https://img.shields.io/pypi/v/http-tls?style=flat-square&color=blue)](https://pypi.org/project/http-tls/)
[![Python](https://img.shields.io/badge/python-3.8%20--%203.14-blue.svg?style=flat-square)](https://www.python.org/)
[![Typing](https://img.shields.io/badge/typing-PEP%20561%20typed-007acc.svg?style=flat-square)](https://peps.python.org/pep-0561/)
[![Rust](https://img.shields.io/badge/rust-PyO3%200.23%20%7C%20Tokio%20%7C%20BoringSSL-orange.svg?style=flat-square)](https://www.rust-lang.org/)

[![CI](https://img.shields.io/github/actions/workflow/status/real-coder-xD/http_tls/release.yml?style=flat-square&label=CI)](https://github.com/real-coder-xD/http_tls/actions)
[![Browser Presets](https://img.shields.io/badge/browser%20presets-100%2B-success.svg?style=flat-square)](#supported-browser-impersonation-presets-100-profiles)
[![Wheels](https://img.shields.io/badge/wheels-5%20platforms-brightgreen.svg?style=flat-square)](https://pypi.org/project/http-tls/#files)
[![Downloads](https://img.shields.io/pypi/dm/http-tls?style=flat-square&color=blue)](https://pypi.org/project/http-tls/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://github.com/real-coder-xD/http_tls/blob/main/LICENSE)

[Why](#why-http_tls) · [Comparison](#comparison-http_tls-vs-curl_cffi-primp-rnet-and-tls-client) · [Benchmarks](#verified-benchmarks--live-ja4--http2-fingerprint-audit) · [Installation](#installation) · [Quick Start](#migration--drop-in-quick-start-requests-httpx-curl_cffi-tls-client) · [Rust Extraction (CSS/XPath/JSON)](#built-in-pure-rust-extraction-html5-css3-xpath-10-json-path--dfa-regex) · [Concurrency](#high-concurrency-execution-native-tokio-async--sync-gather) · [Streaming](#streaming-responses--multipart-file-uploads)<br>
[WebSockets](#tls-impersonated-websockets-sync--async) · [Fingerprint Tuning](#custom-ja3-boringssl-tls_options-http2-settings--wire-header-order) · [Proxies & DoH DNS](#proxies-dns-over-https-doh-custom-resolve--ipv6-64-binding) · [Auth & mTLS](#authentication-basic-bearer-digest-custom-ca-bundles--mutual-tls-mtls) · [Anti-Bot](#waf-challenge-detection-retries-playwright-storage_statejson--solver-bridge) · [Traffic Inspection](#traffic-inspection-wireshark-keylog--har-12-export) · [Presets](#supported-browser-impersonation-presets-100-profiles) · [API Reference](#api-reference-summary) · [Architecture](#architecture-under-the-hood) · [FAQ](#frequently-asked-questions-faq) · [Changelog](CHANGELOG.md)

</div>

`http_tls` (`pip install http-tls`) is a high-performance, standalone **Rust + BoringSSL (`btls`) HTTP client & extraction toolkit for Python** that reproduces byte-exact **TLS (JA3, JA4, GREASE, ALPS, Real ECH, Post-Quantum `X25519MLKEM768`)**, **HTTP/2 (Akamai)**, and **UDP QUIC HTTP/3** browser fingerprints for over 100 Chrome, Safari, Firefox, Edge, Opera, OkHttp, and Tor profiles — and parses HTML/JSON/text responses directly inside Rust (`html5ever` CSS3, native XPath 1.0, `serde_json` JSON Path, linear-time DFA `regex`).

Built on Rust PyO3 (`abi3-py38`), Tokio, `wreq`, `quinn`/`h3`, `dom_query`, and Hickory async DNS, `http_tls` ships as a single self-contained ABI3 wheel with **zero Python runtime dependencies** and works as a drop-in replacement for **`requests`**, **`httpx`**, and **`curl_cffi`**.

```bash
pip install http-tls
```

---

## Key Facts (At a Glance)

| Property | Value |
| :--- | :--- |
| **PyPI Package** | `http-tls` (`pip install http-tls`) |
| **Python Import** | `import http_tls` |
| **TLS / HTTP Engine** | Embedded Rust `wreq` + BoringSSL (`btls`) + `quinn`/`h3` UDP QUIC (HTTP/1.1, HTTP/2 & HTTP/3), zero `libcurl` or Go CGo dependency |
| **Async & DNS Stack** | Native Rust Tokio runtime (`pyo3-async-runtimes`) + Hickory async DNS + **Session-wide DNS-over-HTTPS (`doh=True`)** |
| **Drop-in API Compatibility** | `requests`, `httpx` (`Client`, `AsyncClient`, `stream`), and `curl_cffi` (`BrowserType`, `impersonate`) |
| **Sync Parallelism** | `session.gather(urls, concurrency=50)` — GIL-free multi-request batching without `async/await` |
| **Fingerprinting & HTTP/3** | 100+ browser presets, custom JA3, `tls_options`, `http2_options` (`akamai_h2`), Pure BoringSSL UDP QUIC `http3=True` (per-browser QUIC params & TLS 1.3 ticket resumption `resp.tls_resumed`), **Real ECH (`ech=True` on both TCP H2 & UDP H3 -> `sni=encrypted`)**, **SOCKS5 UDP Associate**, auto `Alt-Svc: h3=":443"` upgrade |
| **Built-in Rust Extraction** | **100% Pure Rust** WHATWG HTML5 CSS3 (`:has()`, `:contains()`, `::text`, `::attr()`), native XPath 1.0, `serde_json` `json_path`, linear-time DFA `re` / `between`, unified `resp.find()` / `resp.find_all()` — zero `lxml`/`bs4` needed |
| **WebSockets & Streaming** | TLS-impersonated sync/async WebSockets, true incremental H2 + H3 streaming, native H2 + H3 multipart `files=` |
| **Reverse Engineering & Ops** | Wireshark `SSLKEYLOGFILE` / `keylog_file`, HAR 1.2 export, Playwright `storage_state.json`, WAF `resp.challenge` detector |
| **Python & Platform Support** | Python 3.8 – 3.14+ (ABI3 wheels) on Windows `x86_64`, Linux `manylinux_2_28` (`x86_64`, `aarch64`), macOS (`x86_64`, `arm64`) |
| **License** | MIT |

---

## Why `http_tls`?

Standard Python HTTP clients (`requests`, `urllib3`, `aiohttp`, `httpx`) rely on the system OpenSSL stack. Their TLS `ClientHello` cipher suites, extensions, elliptic curves, and HTTP/2 `SETTINGS` frames produce non-browser JA3/JA4 signatures that are immediately flagged or throttled by Cloudflare, Akamai, DataDome, PerimeterX, Imperva, and Fastly.

Existing Python TLS-impersonating alternatives each carry architectural trade-offs:
- `▸` `tls-client` wraps a Go CGo shared library (`utls`), which suffers from CGo memory leaks in long-running workers, lacks native `asyncio`, and does not synchronize `cookies.clear()` across the FFI boundary.
- `▸` `curl_cffi` binds `libcurl-impersonate` over CFFI, carrying C memory-management complexity and lacking synchronous Rust-native batching, built-in WAF interstitial detection, HAR recording, or Playwright `storage_state.json` integration.
- `▸` `primp` and `rnet` expose Rust engines but do not provide full drop-in API compatibility with `requests`, `httpx`, and `curl_cffi`.

`http_tls` solves these problems in a single compiled Rust PyO3 module:
- `◈` **Byte-Exact BoringSSL Fingerprinting**: Authentic JA3, JA4, GREASE, ALPS, Post-Quantum `X25519MLKEM768`, and Akamai HTTP/2 frame order for Chrome, Safari, Firefox, Edge, Opera, OkHttp, and Tor.
- `◈` **True Native Async + GIL-Free Sync Batching**: `AsyncSession` maps Rust Tokio futures directly onto Python's `asyncio` event loop with zero `asyncio.to_thread` overhead. Synchronous code can call `session.gather(urls, concurrency=50)` to execute batches concurrently inside Rust while releasing the GIL.
- `◈` **Triple Drop-in API**: Switch from `requests`, `httpx`, or `curl_cffi` by changing a single import line.
- `◈` **Rust RAII Memory Safety**: Shared process-wide Tokio runtime and automatic resource cleanup with minimal Python heap overhead (16.4 KB peak Python allocation in sequential tests).

---

## Comparison: `http_tls` vs `curl_cffi`, `primp`, `rnet`, and `tls-client`

Head-to-head against Python HTTP clients that impersonate browser TLS (JA3/JA4) and HTTP/2 fingerprints. Plain clients such as `requests` and `httpx` are excluded because they expose an OpenSSL ClientHello and cannot impersonate a browser.

| Capability | http_tls | curl_cffi | primp / rnet | tls-client |
| :--- | :--- | :--- | :--- | :--- |
| Fingerprint engine | Rust + Pure BoringSSL (`wreq` + `btls-sys`) | libcurl-impersonate (C/CFFI) | Rust + BoringSSL | Go `utls` (CGo) |
| Browser TLS / JA4 / HTTP/2 presets | `✓` 100+ incl. Safari iOS, OkHttp, Tor | `✓` | `✓` | `✓` |
| Native HTTP/3 (UDP QUIC + `X25519MLKEM768`) | `✓` Pure BoringSSL `quinn`+`h3` + `H3Pool` + TLS 1.3 resumption | `◐` ngtcp2 | `✗` | `✗` |
| Real ECH (`sni=encrypted` via DoH Type 65) | `✓` Both TCP HTTP/2 & UDP HTTP/3 (`ech=True`, `resp.ech_accepted`) | `✗` | `✗` | `✗` |
| Session-Wide DNS-over-HTTPS (`doh=True`) | `✓` Dual-stack `A`+`AAAA` TTL cache (H1/H2/H3) | `✗` | `✗` | `✗` |
| HTTP/3 (UDP QUIC) over SOCKS5 UDP Associate | `✓` RFC 1928/1929 `socks5://` / `socks5h://` | `✗` | `✗` | `✗` |
| Automatic `Alt-Svc: h3=":443"` Upgrade | `✓` w/ TCP H2 Happy Eyeballs fallback | `✗` | `✗` | `✗` |
| Built-in Pure Rust CSS3 / XPath / JSON / Regex | `✓` `resp.css()`, `xpath()`, `find()`, `json_path()`, `re()` (0 deps) | `✗` | `✗` | `✗` |
| Custom JA3, Akamai H2, TLS & H2 Options | `✓` | `✓` | `◐` | `✓` |
| Exact Wire Header Order (`OrigHeaderMap`) | `✓` | `◐` | `✓` | `✓` |
| Native Event-Loop Async | `✓` Tokio | `✓` libcurl | `✓` Tokio | `✗` |
| Sync Parallel `gather()` (No `async/await`) | `✓` Rust Tokio | `✗` | `✗` | `✗` |
| `requests` + `httpx` + `curl_cffi` Drop-in | `✓` | `◐` `requests`-style | `◐` `requests`-style | `◐` `requests`-style |
| Async Hickory DNS & Custom `resolve` | `✓` | `◐` `resolve` only | `◐` | `✗` |
| Outbound IPv4 / IPv6 `/64` Socket Binding | `✓` | `✓` | `◐` | `✗` |
| TLS-Impersonated WebSockets (Sync & Async) | `✓` | `✓` | `◐` | `✗` |
| Streaming, Multipart, Custom CA, mTLS | `✓` | `✓` | `◐` | `◐` |
| RFC 7616 `DigestAuth` (MD5/SHA-256/512) | `✓` | `✗` | `✗` | `✗` |
| Deep `cookies.clear()` Sync Across FFI | `✓` | `✓` | `✓` | `✗` Broken |
| Built-in WAF `resp.challenge` Detector | `✓` | `✗` | `✗` | `✗` |
| Playwright `storage_state.json` & Solver Bridge | `✓` | `✗` | `✗` | `✗` |
| Wireshark `keylog_file` & HAR 1.2 Export | `✓` | `✗` | `✗` | `✗` |
| Memory Safety (No CGo / Manual Free) | `✓` Rust RAII | `◐` C/CFFI | `✓` Rust RAII | `✗` Go CGo leaks |

> Legend: `✓` Native / full support · `◐` Partial / indirect · `✗` Not built-in

---

## Verified Benchmarks & Live JA4 / HTTP/2 Fingerprint Audit

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

### 1b. Live Pure BoringSSL HTTP/3 (UDP QUIC), Real ECH (TCP H2 & UDP H3), TLS 1.3 Ticket Resumption & SOCKS5 UDP Associate

Unlike Rust clients that fall back to `rustls` for QUIC, `http_tls` drives `quinn` + `h3` directly through **BoringSSL (`SSL_CTX_set_quic_method`)** with Chrome GREASE, extension permutation, Post-Quantum `X25519MLKEM768`, **Real ECH (`SSL_set1_ech_config_list` + DoH DNS Type 65 `HTTPS` record + automatic `SSL_get0_ech_retry_configs` retry on both TCP HTTP/2 and UDP HTTP/3)**, ALPS `h2`/`h3`, Brotli/Zlib/Zstd cert compression, **per-browser QUIC transport parameters (`0x0039` for Chrome, Firefox, Safari)**, **TLS 1.3 Session Ticket Resumption (`resp.tls_resumed`)**, `H3Pool` multiplexing, native H3 multipart `files=` uploads, and **RFC 1928 / RFC 1929 SOCKS5 UDP Associate** proxying:

```python
import http_tls

# 1. Real ECH (Encrypted Client Hello -> sni=encrypted) over Pure BoringSSL HTTP/3
with http_tls.Session(impersonate="chrome_149", http3=True, ech=True) as s:
    r = s.get("https://cloudflare-ech.com/cdn-cgi/trace")
    # r.http_version == "HTTP/3"
    # r.ech_accepted == True
    # Cloudflare trace confirms:
    #   http=http/3
    #   tls=TLSv1.3
    #   sni=encrypted
    #   kex=X25519MLKEM768

# 2. Real ECH over TCP HTTP/2 (works even when UDP 443 is blocked or target only serves h2)
with http_tls.Session(impersonate="chrome_149", ech=True, auto_upgrade_h3=False) as s:
    r = s.get("https://crypto.cloudflare.com/cdn-cgi/trace")
    # r.http_version == "HTTP/2"
    # r.ech_accepted == True  (sni=encrypted)

# 3. HTTP/3 (UDP QUIC) + Real ECH tunneled over an authenticated SOCKS5 UDP Associate proxy
with http_tls.Session(
    impersonate="chrome_149",
    http3=True,
    ech=True,
    proxy="socks5://user:pass@127.0.0.1:1080",
) as s:
    r = s.get("https://cloudflare-ech.com/cdn-cgi/trace")
    # Tunnels QUIC UDP datagrams through SOCKS5 CMD=0x03 (UDP ASSOCIATE)
    # Automatic graceful fallback to TCP HTTP/2 if proxy rejects UDP ASSOCIATE (unless http3_only=True)

# 4. QUIC TLS 1.3 Session Ticket Resumption & Automatic Alt-Svc: h3=":443" Upgrade
with http_tls.Session(impersonate="chrome_149") as s:
    r1 = s.head("https://www.cloudflare.com/")              # HTTP/2 -> caches Alt-Svc: h3=":443"
    r2 = s.get("https://www.cloudflare.com/cdn-cgi/trace")  # Auto-upgrades to UDP QUIC HTTP/3
    # Reconnects automatically resume via captured TLS 1.3 session tickets (r.tls_resumed == True)
```

### 2. Throughput, Latency & Python Heap Usage (`https://www.cloudflare.com/cdn-cgi/trace`)

Reproduce locally with `python benchmarks/bench_vs_competitors.py`:

**Sequential Synchronous Benchmark (15 requests, warm connection):**

| Python HTTP Client | Median Latency | Throughput | Peak Python Memory (`tracemalloc`) |
| :--- | ---: | ---: | ---: |
| `▸` `http_tls` (Rust BoringSSL) | 38.0 ms | 24.4 req/s | 16.4 KB |
| `▸` `curl_cffi` | 47.2 ms | 10.4 req/s | 19.2 KB |

**Concurrent Asynchronous Benchmark (30 simultaneous requests):**

| Python Async HTTP Client | Average per Request | Throughput | Peak Python Memory (`tracemalloc`) |
| :--- | ---: | ---: | ---: |
| `▸` `http_tls.AsyncSession` (Native Tokio) | 2.9 ms | 346.0 req/s | 200.0 KB |
| `▸` `curl_cffi.AsyncSession` | 4.7 ms | 211.4 req/s | 234.6 KB |

Against `curl_cffi`, the most widely used fingerprinting client, `http_tls` delivers **1.24x faster median sync latency**, **2.35x higher sync throughput**, and **1.64x higher async throughput** at 30-way concurrency while allocating less Python heap memory.

### 3. Pure Rust Extraction Speed (HTML5 CSS3, XPath 1.0, DFA Regex & JSON Path)

Reproduce locally with `python benchmarks/bench_extraction.py` (105.7 KB HTML / 500 product cards, 33.5 KB JSON / 500 items, median of 30 runs):

| Workload | `http_tls` (Pure Rust) | Baseline | Result |
| :--- | ---: | ---: | :--- |
| Full HTML5 parse + CSS3 (`500 hrefs`) | **2.87 ms** | `BeautifulSoup (html.parser)`: 60.23 ms | **21.0x faster** |
| Cached DOM CSS3 (`:not(.sold-out) a::attr(href)`) | **0.094 ms** | `BeautifulSoup .select()`: 6.90 ms | **73.6x faster** |
| Cached DOM XPath 1.0 (`contains` + `not` + `/@attr`) | **1.05 ms** | — | Zero `lxml` / C deps |
| Delimiter slicing `between_all()` (`500 hrefs`) | **0.062 ms** | Python `re.compile().findall()`: 0.078 ms | **1.26x faster** |
| Cached Rust DFA `re()` (`500 matches`, ReDoS-safe) | **0.108 ms** | Python `re.compile().findall()`: 0.078 ms | Linear-time DFA guarantee |
| Recursive JSON Path `$..price` (`501 matches`) | **0.312 ms** | `json.loads()` + listcomp: 0.282 ms | Native `serde_json` speed |

---

## Installation

Prebuilt ABI3 wheels are published on PyPI for Windows (`x86_64`), Linux (`manylinux_2_28` `x86_64` and `aarch64`), and macOS (`x86_64` and `arm64`), supporting Python 3.8 through 3.14+ with zero Python runtime dependencies:

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

## Migration & Drop-in Quick Start (`requests`, `httpx`, `curl_cffi`, `tls-client`)

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

## Built-in Pure Rust Extraction: HTML5 CSS3, XPath 1.0, JSON Path & DFA Regex

Every `Response` ships with a **100% Pure Rust** extraction engine compiled directly into `http_tls._core` — zero `beautifulsoup4`, zero `lxml`, zero `parsel`, zero `jsonpath` dependencies, and zero Python parsing overhead:

- `◈` **WHATWG HTML5 + CSS3 (`dom_query` / `html5ever`)**: Tolerates broken/unclosed real-world HTML just like Chrome/Firefox, supports `:has()`, `:not()`, `:contains()`, `:has-text()`, Scrapy-style `::text` & `::attr(name)`, BeautifulSoup aliases (`select()`, `select_one()`, `get_text()`), `selectolax`-style `own_text` & DOM navigation (`parent`, `children`, `next_sibling`, `prev_sibling`, `ancestors`), and Scrapy `urljoin()` + `attrib` + `default=` fallbacks.
- `◈` **Native Rust XPath 1.0**: Walks the Rust HTML5 DOM tree directly without re-parsing — supports `//`, `/`, `.`, `..`, `*`, `|`, parenthesized groups `(//div[...])[1]/@attr`, all core axes (`child::`, `descendant::`, `parent::`, `ancestor::`, `following-sibling::`, `preceding-sibling::`, `following::`, `preceding::`, `self::`, `attribute::`), and predicates (`and`/`or`/`not`, `contains()`, `starts-with()`, `ends-with()`, `normalize-space()`, `string-length()`, `count()`, `substring-before()`, `substring-after()`, `[1]`, `[last()]`, `[position()=n]`, `/text()`, `/@attr`).
- `◈` **Structured JSON Path (`serde_json`)**: Extract nested keys, quoted keys (`meta["content-type"]`), negative indices (`items[-1].id`), array slices (`items[0:5]`), wildcards (`items[*].name`), and **recursive descent (`$..price`)** across deeply nested SPA / GraphQL / `__NEXT_DATA__` payloads.
- `◈` **ReDoS-Safe Linear-Time DFA Regex & Delimiter Slicing (`regex`)**: `resp.re()`, `resp.re_first()`, `resp.between()`, and `resp.between_all()` run inside Rust with guaranteed linear-time execution (immune to catastrophic backtracking).
- `◈` **Lazy & Thread-Safe DOM Caching**: The HTML5 DOM is parsed only on the first `css`/`xpath`/`find` call and cached inside an `Arc<Mutex<...>>` so a `Response`, `HtmlDocument`, or `Element` can safely cross `ThreadPoolExecutor` or `asyncio.to_thread` boundaries.

```python
import http_tls

r = http_tls.get("https://shop.example/catalog")

# 1. CSS3 selectors (+ :has(), :contains(), Scrapy ::text & ::attr())
title = r.css_first("title::text")
links = r.css("div.card:not(.sold-out) a.buy::attr(href)")
match = r.css("div.card:has(span.price:contains('$42.50')) a::attr(href)")

# Chain queries & DOM navigation on Element (BeautifulSoup / selectolax / Scrapy idioms)
card = r.select_one("div.card.featured")
if card is not None:
    print(card.tag, card["data-id"], card.attrib["data-id"], card.attr("data-sku", "n/a"))
    print(card.own_text.strip(), card.get_text(" | "))
    print(card.parent.tag, card.next_sibling["data-id"], r.urljoin(card.find(".//a/@href")))

# 2. Native Rust XPath 1.0 (axes, predicates, parenthesized groups, unions)
ids = r.xpath("//div[contains(@class, 'card') and not(contains(@class, 'sold-out'))]/@data-id")
next_price = r.xpath_first("//h2[normalize-space(.)='Gamma Tool']/following-sibling::span[1]/text()")
next_h2 = r.xpath_first("//h2[normalize-space(.)='Alpha Widget']/following::h2[1]/text()")
last_id = r.xpath_first("(//div[contains(@class, 'card')])[last()]/@data-id")
both = r.xpath("//title/text() | //main/@data-env")

# 3. Unified find() / find_all() auto-routing (JSON "$." / "$.." / "$[", XPath, or CSS3)
first_price = r.find("div.card.featured .price::text", default="N/A")   # routes to CSS3
first_href = r.find("//div[@data-id='102']/a/@href")                    # routes to XPath 1.0
all_hrefs = r.find_all("a.buy::attr(href)")                             # routes to CSS3

# 4. ReDoS-safe Rust DFA Regex & fast delimiter slicing
token = r.re_first(r'__TOKEN__\s*=\s*"([^"]+)"', default="")
prices = r.re(r"\$(\d+\.\d{2})")
csrf = r.between('name="csrf" value="', '"')
all_hrefs_fast = r.between_all('href="', '"')

# 5. Structured JSON Path (serde_json) on API responses (dot, slices, wildcards, recursive $..key)
api = http_tls.get("https://api.example/v1/items")
names = api.json_path("items[*].name")                   # ["a", "b", "c"]
top2 = api.json_path("items[0:2].name")                  # ["a", "b"]
all_prices = api.json_path("$..price")                   # recursive descent at any depth
last_item_id = api.json_path("items[-1].id", default=0)  # 3
first_ok = api.find("$.meta.ok")                         # True (auto-routed via "$.")
```

### Auto-Routing Rules for `find()` / `find_all()`

| Query Pattern | Routed Engine | Example |
| :--- | :--- | :--- |
| Starts with `$.`, `$..`, or `$[` | Rust `serde_json` JSON Path | `r.find("$.items[-1].id")`, `r.find_all("$..price")`, `r.find("$[0].lat")` |
| Starts with `/`, `./`, `../`, `(`, `@`, or contains an XPath axis (`following-sibling::`, `following::`, `preceding::`, `ancestor::`, `parent::`, ...) | Native Rust XPath 1.0 | `r.find("//h1/text()")`, `r.find("(//a)[last()]/@href")` |
| Anything else (including `::text` & `::attr(name)`) | Rust HTML5 CSS3 (`dom_query`) | `r.find("div.price::text")`, `r.find_all("a::attr(href)")` |

### Migrating Extraction Code from `BeautifulSoup`, `Scrapy/parsel`, `selectolax` & `lxml`

| Familiar Idiom | `http_tls` Built-in Rust Equivalent |
| :--- | :--- |
| `soup.select("a.buy")` / `soup.select_one("h1")` | `r.select("a.buy")` / `r.select_one("h1", default=None)` |
| `el.get_text(" ", strip=True)` | `el.get_text(" ", strip=True)` (also on `Response` & `HtmlDocument`) |
| `selectolax` `node.text(deep=False)` / `node.next` / `node.prev` | `el.own_text` / `el.next_sibling` / `el.prev_sibling` / `el.parent` / `el.children` / `el.ancestors` |
| Scrapy `resp.css("a::attr(href)").get(default="")` / `resp.urljoin(u)` | `r.css_first("a::attr(href)", default="")` / `r.urljoin(u)` / `el.attrib` |
| `lxml` `tree.xpath("//h2/following::span[1]/text()")` | `r.xpath_first("//h2/following::span[1]/text()", default="")` |
| `jsonpath` `parse("$..price").find(data)` | `r.json_path("$..price")` / `r.json_path("items[0:5].name")` |

Invalid CSS, XPath, regex, or JSON queries raise `ValueError` cleanly instead of crashing. You can also parse standalone HTML strings directly via `from http_tls import HtmlDocument` (`doc = HtmlDocument(html_str)`).

---

## High-Concurrency Execution: Native Tokio Async & Sync `gather()`

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

## Streaming Responses & Multipart File Uploads

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

## TLS-Impersonated WebSockets (Sync & Async)

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

## Custom JA3, BoringSSL `tls_options`, HTTP/2 Settings & Wire Header Order

For custom mobile clients, non-standard APIs, or fingerprint research, override TLS parameters, HTTP/2 settings, and exact wire header casing and ordering (`OrigHeaderMap`):

```python
import http_tls

with http_tls.Session(
    # Standard 5-field JA3 string
    ja3="771,4865-4866-4867-49195-49199,0-23-65281,29-23-24,0",
    # 1-line Akamai HTTP/2 fingerprint override (SETTINGS|WINDOW_UPDATE|PRIORITIES|PSEUDO_ORDER)
    akamai_h2="1:65536;2:0;4:2097152;6:262144|10420225|0|m,s,a,p",
    # Fine-grained BoringSSL configuration
    tls_options={
        "alpn": ["h2", "http/1.1"],
        "alps_protocols": ["h2"],
        "grease_enabled": True,
        "permute_extensions": True,
        "enable_ech_grease": True,
        "enable_ocsp_stapling": True,
        "certificate_compressors": ["brotli", "zlib", "zstd"],
        "extension_permutation": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43, 27],
    },
    # Full HTTP/2 frame control (or override individual fields parsed from akamai_h2)
    http2_options={
        "header_table_size": 65536,
        "enable_push": False,
        "initial_window_size": 6291456,
        "max_header_list_size": 262144,
        "settings_order": [1, 2, 4, 6],
        "headers_pseudo_order": ["m", "a", "s", "p"],
        "headers_stream_dependency": {"stream_id": 0, "weight": 219, "exclusive": True},
    },
    # Enforce exact wire header order and casing
    header_order=["Host", "Connection", "User-Agent", "Accept", "Accept-Language"],
    # Optional protocol forcing: http1_only=True or http2_only=True
) as s:
    resp = s.get("https://tls.peet.ws/api/all")
```

---

## Proxies, DNS-over-HTTPS (DoH), Custom `resolve` & IPv6 `/64` Binding

`http_tls` uses **Hickory async DNS** by default (eliminating OS resolver thread contention), includes **Session-wide DNS-over-HTTPS (`doh=True`)** with concurrent dual-stack `A`+`AAAA` lookups and TTL caching across HTTP/1.1, HTTP/2, and HTTP/3, supports HTTP/HTTPS/SOCKS5 proxies (including **SOCKS5 UDP Associate** for HTTP/3) with round-robin pools, overrides DNS resolution per hostname without breaking TLS SNI, and binds outbound IPv4/IPv6 addresses for proxy-less IPv6 `/64` rotation:

```python
import http_tls

# Single HTTP / HTTPS / SOCKS5 proxy (works for TCP H1/H2 and UDP QUIC H3 via SOCKS5 UDP Associate)
r = http_tls.get("https://api.ipify.org?format=json", proxy="socks5://user:pass@1.2.3.4:1080")

# Session-wide DNS-over-HTTPS (eliminates plaintext ISP/OS DNS leaks across H1, H2, and H3)
with http_tls.Session(
    impersonate="chrome_149",
    doh=True,                                        # Uses Cloudflare DoH by default
    doh_url="https://dns.google/resolve",            # Optional custom JSON DoH endpoint
    ech=True,                                        # Combine with Real ECH for encrypted DNS + encrypted SNI
) as s:
    r = s.get("https://cloudflare-ech.com/cdn-cgi/trace")
    print(r.http_version, r.ech_accepted)

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

## Authentication (`Basic`, `Bearer`, `Digest`), Custom CA Bundles & Mutual TLS (mTLS)

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

## WAF Challenge Detection, Retries, Playwright `storage_state.json` & Solver Bridge

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

### 2. Browser Solver Bridges (`BestDriverSolver`, `PlaywrightSolver`, `FlareSolverrSolver`) & `storage_state.json`

`http_tls` is a pure HTTP client (no embedded V8 engine). For L4/L7 TLS + HTTP/2 fingerprinting it handles traffic natively in Rust; when a target serves a JavaScript proof-of-work or Turnstile challenge (`resp.challenge is not None`), bridge directly to a stealth browser solver or reuse Playwright / Camoufox `storage_state.json`.

- `◈` **Automatic Fingerprint Alignment**: `load_storage_state()` and all built-in solvers extract `User-Agent` and `Sec-CH-UA*` Client Hints, infer the matching verified preset via `infer_impersonate_from_user_agent()`, and hot-swap the active Rust BoringSSL + HTTP/2 profile via `session.set_impersonate()` so TLS JA4, HTTP/2 `SETTINGS`, Client Hints, and `User-Agent` never mismatch.
- `◈` **Per-Domain Singleflight & Warm Browser Reuse**: Concurrent challenge solves on the same domain coalesce into a single browser run with a TTL clearance cache (`cache_ttl=15.0`) and optional warm browser reuse (`keep_warm=True`), preventing Thundering Herd process storms.
- `◈` **Active Turnstile Checkbox Clicking**: `BestDriverSolver` and `PlaywrightSolver` actively locate and click Cloudflare Turnstile checkboxes (piercing open/closed Shadow DOM and challenge iframes with humanized cursor movement).

```python
import http_tls
from http_tls import BestDriverSolver, FlareSolverrSolver

# Load cookies + User-Agent from Playwright context.storage_state(path="state.json")
# Automatically aligns Rust TLS/H2 impersonation profile with the User-Agent version & OS
with http_tls.Session(
    storage_state="state.json",
    auto_referer=True,        # Chains Referer across navigations like a real browser
    fetch_mode="same-origin", # Emits coherent Sec-Fetch-Mode / Site / Dest headers
) as s:
    resp = s.get("https://protected.example.com/api/data")
    s.save_storage_state("state.json")

# Automatic stealth Chromium bridge (best-driver) on JS challenges — works in both sync & async
with http_tls.Session(
    retries=1,
    retry_on_challenge=True,
    solver=BestDriverSolver(headless=True, keep_warm=True, click_turnstile=True),
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

## Traffic Inspection: Wireshark KeyLog & HAR 1.2 Export

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

## Supported Browser Impersonation Presets (100+ Profiles)

Every preset returned by `http_tls.supported_presets()` is a **verified native BoringSSL + HTTP/2 profile** with zero header extrapolation (auditable at runtime via `http_tls.is_verified_preset(name)`). The default preset is `chrome_149`:

- `▸` **Google Chrome (`chrome_100` – `chrome_149`)**: Desktop Windows/Linux, macOS (`chrome_149_macos`), and Android (`chrome_131_android`).
- `▸` **Microsoft Edge (`edge_101` – `edge_148`)**: `edge_148`, `edge_147`, `edge_146`, `edge_145`, `edge_142`, `edge_134`, `edge_131`, `edge_127`, `edge_122`, `edge_101`.
- `▸` **Apple Safari (`safari_15_3` – `safari_26_4`)**: macOS (`safari_26_4`, `safari_26_3`, `safari_26_2`, `safari_26_1`, `safari_26`, `safari_18_5`, `safari_18`, `safari_17_6`), iOS (`safari_ios_26_2`, `safari_ios_26`, `safari_ios_18_1_1`), and iPadOS (`safari_ipad_26_2`, `safari_ipad_26`, `safari_ipad_18`).
- `▸` **Mozilla Firefox (`firefox_109` – `firefox_151`)**: Desktop, private browsing (`firefox_private_136`, `firefox_private_135`), and Android (`firefox_android_135`).
- `▸` **Opera (`opera_116` – `opera_131`)**: `opera_131`, `opera_130`, `opera_128`, `opera_124`, `opera_120`, `opera_116`.
- `▸` **OkHttp (Android)**: `okhttp_5`, `okhttp_4_12`, `okhttp_4_10`, `okhttp_4_9`, `okhttp_3_14`, `okhttp_3_11`, `okhttp_3_9`.
- `▸` **Tor & Automatic Rotation**: `tor_14_5`, `random`, and `weighted_random` (market-share weighted browser + OS selection).

---

## Architecture Under the Hood

```text
┌────────────────────────────────────────────────────────────┐
│                     Python Application                     │
│      import http_tls as requests / httpx / curl_cffi       │
└─────────────────────────────┬──────────────────────────────┘
                              │ http_tls package (PEP 561 typed)
                              ▼
┌────────────────────────────────────────────────────────────┐
│                  Python Layer (http_tls)                   │
│  ▸ Session · AsyncSession · Client · AsyncClient           │
│  ▸ Retries · proxy pool · WAF challenge detector           │
│  ▸ Basic / Bearer / Digest auth · storage_state · HAR      │
└─────────────────────────────┬──────────────────────────────┘
                              │ PyO3 0.23 (abi3-py38) · GIL released on I/O
                              ▼
┌────────────────────────────────────────────────────────────┐
│             Rust Core (http_tls._core cdylib)              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │          Shared Tokio Multi-Thread Runtime           │  │
│  │  ▸ wreq HTTP/1.1 + HTTP/2 engine (OrigHeaderMap)     │  │
│  │  ▸ quinn + h3 UDP QUIC HTTP/3 engine + H3Pool        │  │
│  │  ▸ Pure BoringSSL (btls-sys): GREASE · ALPS · MLKEM  │  │
│  │  ▸ wreq-util browser emulation (100+ presets)        │  │
│  │  ▸ Hickory async DNS · DoH (doh=True) · resolve      │  │
│  │  ▸ RFC 6265 Cookie jar · multipart (H2+H3) · WS      │  │
│  │  ▸ Pure Rust HTML5 CSS3 / XPath 1.0 / JSON / Regex   │  │
│  │  ▸ Buffered gather() scheduler (H2 + H3 multiplexed) │  │
│  └──────────────────────────┬───────────────────────────┘  │
└─────────────────────────────┼──────────────────────────────┘
                              │ TCP TLS 1.3 / HTTP/2  +  UDP QUIC / HTTP/3
                              ▼
┌────────────────────────────────────────────────────────────┐
│                  Target Server / WAF Edge                  │
│  (Cloudflare · Akamai · DataDome · PerimeterX · Imperva)   │
│  ▸ Observes a byte-identical Chrome / Safari / Firefox     │
└────────────────────────────────────────────────────────────┘
```

### Source Layout

| File | Responsibility |
| :--- | :--- |
| `src/lib.rs` | PyO3 module: `NativeSession`, sync/async request paths, incremental H2 + H3 streaming, `gather()` scheduler, `H3Pool`, WebSocket bridge, TLS/H2 option builders, DNS overrides, KeyLog wiring. |
| `src/quic_boring.rs` | Pure BoringSSL (`btls-sys`) `quinn_proto::crypto` provider: `SSL_CTX_set_quic_method`, Chromium/Firefox/Safari QUIC Initial `ClientHello` (`X25519MLKEM768`, GREASE, ALPS `h3`, Real ECH, Brotli/Zlib/Zstd cert compression), TLS 1.3 ticket resumption, RFC 9001 AEAD/HP. |
| `src/tcp_ech.rs` | Pure BoringSSL TCP HTTP/2 Real ECH transport (`btls` + `tokio-btls` + `http2`) with `SSL_set1_ech_config_list`, auto retry-config handling, TLS 1.3 ticket capture, SOCKS5 TCP CONNECT, and incremental H2 streaming. |
| `src/doh.rs` | Session-wide DNS-over-HTTPS (`wreq::dns::Resolve`) with concurrent dual-stack `A`+`AAAA` lookups and bounded TTL caching across H1, H2, and H3. |
| `src/socks5_udp.rs` | RFC 1928 / RFC 1929 SOCKS5 `UDP ASSOCIATE` socket (`quinn::AsyncUdpSocket`) with source relay verification for tunneling HTTP/3 over SOCKS5 proxies. |
| `src/extract.rs` | 100% Pure Rust extraction engine: `dom_query` (`html5ever`) CSS3 + `::text`/`::attr()`, native XPath 1.0 evaluator, `serde_json` JSON Path, linear-time DFA `regex`, and thread-safe `HtmlDocument` / `Element` PyO3 classes. |
| `python/http_tls/requests.py` | Public API: `Session`, `AsyncSession`, `Client`, `AsyncClient`, `Response` (incl. `css`, `xpath`, `find`, `re`, `between`, `json_path`), `Cookies`, retries, proxy pool, HAR recorder, `storage_state`, solver bridge, `event_hooks`. |
| `python/http_tls/auth.py` | `AuthBase`, `BasicAuth`, `BearerAuth`, RFC 7616 `DigestAuth` (sync & async). |
| `python/http_tls/challenge.py` | Interstitial detector for Cloudflare, DDoS-Guard, DataDome, PerimeterX, Imperva, Sucuri, Vercel, Akamai. |
| `python/http_tls/solvers.py` | Optional browser challenge solver bridges (`BestDriverSolver`, `PlaywrightSolver`, `FlareSolverrSolver`). |
| `python/http_tls/exceptions.py` | Unified `requests` / `httpx` / `curl_cffi` exception hierarchy. |
| `python/http_tls/__init__.pyi` | PEP 561 type stubs (shipped with `py.typed`). |

---

## API Reference Summary

### `Session` / `Client` / `AsyncSession` / `AsyncClient` Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `impersonate` | `str \| BrowserType` | `"chrome_149"` | Verified native browser TLS + HTTP/2 + header profile |
| `base_url` | `str` | `""` | Base URL prepended to relative request paths |
| `timeout` / `connect_timeout` / `read_timeout` | `float \| tuple \| TimeoutConfig` | `30.0` | Total, `(connect, read)` tuple, or granular `TimeoutConfig` |
| `limits` / `pool_max_idle_per_host` / `pool_idle_timeout` | `Limits \| int \| float` | `None` | Connection pool limits (`httpx.Limits`-compatible) |
| `tcp_nodelay` / `tcp_keepalive` | `bool \| float` | `None` | Low-level TCP socket tuning |
| `verify` | `bool \| str` | `True` | `True`, `False`, or path to a custom CA `.pem`/`.der` bundle |
| `cert` | `str \| tuple[str, str]` | `None` | Client mTLS certificate (`combined.pem` or `(crt, key)`) |
| `proxy` / `proxies` / `proxies_pool` | `str \| dict \| list` | `None` | HTTP/HTTPS/SOCKS5 proxy or round-robin proxy list |
| `headers` / `header_order` | `dict \| list[str]` | `None` | Default headers and exact wire header order/casing |
| `params` / `cookies` | `dict` | `None` | Default query parameters and session cookies |
| `auth` | `tuple \| AuthBase` | `None` | `(user, pass)`, `BasicAuth`, `BearerAuth`, or `DigestAuth` |
| `ja3` / `akamai_h2` / `tls_options` / `http2_options` | `str \| dict` | `None` | Custom JA3, Akamai H2 string, and full BoringSSL / H2 overrides |
| `http1_only` / `http2_only` / `http3` / `http3_only` | `bool` | `False` | Force HTTP/1.1, HTTP/2, or pure BoringSSL UDP QUIC HTTP/3 |
| `auto_upgrade_h3` | `bool` | `True` | Automatically upgrade to UDP QUIC HTTP/3 on `Alt-Svc: h3` (w/ TCP fallback) |
| `ech` / `ech_doh_url` | `bool \| str` | `False` | Real Encrypted Client Hello (`sni=encrypted`) on both TCP H2 and UDP H3 (pass custom `ech_config_list=bytes` per request) |
| `doh` / `doh_url` | `bool \| str` | `False` | Session-wide DNS-over-HTTPS (`A`+`AAAA` dual-stack TTL cache across H1/H2/H3) |
| `resolve` | `dict[str, str \| list]` | `None` | Custom DNS / origin IP mapping (`{"host": "ip"}`) |
| `local_address` / `interface` | `str` | `None` | Bind outbound IPv4/IPv6 address or network interface |
| `system_dns` | `bool` | `False` | Disable built-in Hickory async DNS and use OS resolver |
| `auto_referer` / `fetch_mode` | `bool \| str` | `False` / `None` | Chain `Referer` and emit coherent `Sec-Fetch-*` headers |
| `retries` / `retry_backoff` / `retry_statuses` | `int \| float \| tuple` | `0` | Automatic retry count, exponential backoff base, and status codes |
| `retry_on_challenge` / `rotate_impersonate` | `bool` | `False` | Auto-retry and rotate preset/proxy on WAF challenge |
| `storage_state` / `flare_solverr_url` / `solver` | `str \| dict \| callable` | `None` | Playwright `storage_state.json`, `BestDriverSolver`, or FlareSolverr |
| `tls_info` / `keylog_file` / `record_har` | `bool \| str` | `False` | Capture peer cert DER, write Wireshark keylog, record HAR 1.2 |
| `transport` / `event_hooks` | `MockTransport \| dict` | `None` | Offline `MockTransport` for unit tests and sync/async event hooks |

### Key `Response` Attributes & Methods

- `▸` **Metadata**: `status_code`, `reason`, `reason_phrase`, `url`, `http_version`, `headers`, `cookies`, `elapsed`, `history`, `remote_addr`, `peer_certificate`, `links`, `num_bytes_downloaded`, `challenge`, `alt_svc`, `ech_accepted`, `tls_resumed`.
- `▸` **Status Helpers**: `ok`, `is_success`, `is_informational`, `is_redirect`, `is_permanent_redirect`, `has_redirect_location`, `is_client_error`, `is_server_error`, `is_error`, `raise_for_status()`.
- `▸` **Body & Streaming**: `content`, `text`, `json()`, `read()`, `aread()`, `acontent()`, `atext()`, `iter_content()`, `iter_bytes()`, `iter_text()`, `iter_lines()`, `aiter_bytes()`, `aiter_content()`, `aiter_text()`, `aiter_lines()`, `close()`, `aclose()`.
- `▸` **Pure Rust Extraction**: `html_doc`, `css()`, `css_first()`, `select()`, `select_one()`, `xpath()`, `xpath_first()`, `find()`, `find_all()`, `get_text()`, `urljoin()`, `re()`, `re_first()`, `between()`, `between_all()`, `json_path()` (plus `Element.own_text`, `attrib`, `parent`, `children`, `next_sibling`, `prev_sibling`, `ancestors`).

### Exception Hierarchy (`http_tls.exceptions`)

Compatible with `requests`, `httpx`, and `curl_cffi` exception names:

`RequestException` (`RequestError`, `RequestsError`), `HTTPError` (`HTTPStatusError`), `ConnectionError` (`ConnectError`), `Timeout` (`TimeoutException`), `ConnectTimeout`, `ReadTimeout`, `SSLError`, `TooManyRedirects`, `InvalidURL`.

---

## Frequently Asked Questions (FAQ)

### How does `http_tls` differ from `curl_cffi`?
`http_tls` is compiled in Rust against BoringSSL (`btls`) and Tokio rather than wrapping `libcurl` via CFFI. In live benchmarks against Cloudflare, `http_tls` achieves higher sync and async throughput (346 req/s vs 211 req/s at 30-way concurrency), adds GIL-free parallel `session.gather()` for synchronous code, and includes built-in WAF challenge detection, RFC 7616 Digest Auth, HAR 1.2 export, Wireshark `keylog_file`, and Playwright `storage_state.json` support.

### Does `http_tls` require `libcurl`, Go, `lxml`, or external binaries?
No. BoringSSL, Tokio, HTTP/2, QUIC HTTP/3, Hickory DNS, DoH, `html5ever` CSS3/XPath, `serde_json`, and DFA `regex` are all compiled directly into the native PyO3 extension inside one self-contained ABI3 wheel. Installing via `pip install http-tls` requires zero external runtime dependencies.

### Can `http_tls` replace `BeautifulSoup`, `lxml`, or `parsel` for HTML & JSON scraping?
Yes for the vast majority of scraping and API extraction workloads. `http_tls` embeds a 100% Pure Rust WHATWG HTML5 parser (`html5ever` / `dom_query`), native XPath 1.0 evaluator, `serde_json` JSON Path (`$..key`, slices, wildcards), and cached ReDoS-safe DFA regex directly on `Response` (`css`, `select`, `xpath`, `find`, `json_path`, `re`, `between_all`) — running **21x–73x faster than `BeautifulSoup`** with zero extra Python packages to install.

### Does `http_tls` support Real ECH over TCP HTTP/2 and DNS-over-HTTPS (DoH)?
Yes. Pass `ech=True` to encrypt the TLS SNI (`sni=encrypted` via BoringSSL `SSL_set1_ech_config_list` + DoH DNS Type 65 `HTTPS` records) on **both** TCP HTTP/2 (`crypto.cloudflare.com`) and UDP QUIC HTTP/3 (`cloudflare-ech.com`), and verify via `resp.ech_accepted`. Combine with `doh=True` (or `doh_url="https://dns.google/resolve"`) to route all DNS queries over encrypted DNS-over-HTTPS across HTTP/1.1, HTTP/2, and HTTP/3.

### How can I send concurrent requests in `http_tls` without writing `async/await`?
Use `session.gather(urls, concurrency=50)`. It executes all requests in parallel on the Rust Tokio multi-thread runtime while releasing Python's GIL and returns responses in the exact input order.

### How do I reuse Playwright or Camoufox clearance cookies in `http_tls`?
Export browser cookies with `context.storage_state(path="state.json")` and pass `storage_state="state.json"` to `http_tls.Session(...)`. `http_tls` loads all matching cookies and User-Agent headers into the Rust cookie jar and can write updated cookies back with `session.save_storage_state("state.json")`.

### How do I decrypt and inspect `http_tls` HTTPS / HTTP/2 traffic in Wireshark?
Pass `keylog_file="sslkeys.log"` to `Session(...)` (or set the `SSLKEYLOGFILE` environment variable), then point Wireshark's `Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename` to that file.

### Which Python versions and operating systems are supported?
`http_tls` publishes prebuilt ABI3 wheels (`cp38-abi3`) covering Python 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, and 3.14+ on Windows (`x86_64`), Linux (`manylinux_2_28` `x86_64` and `aarch64`), and macOS (`x86_64` and Apple Silicon `arm64`).

---

## Testing & Development

Run the full pytest suite (46 integration, fingerprint, ECH H2/H3, DoH, SOCKS5 UDP, pure Rust extraction, solver-alignment, singleflight, RFC 6265 cookie-isolation, production-readiness, and soak tests):

```bash
pip install -e ".[test]"
pytest -v tests/
```

Run the standalone high-volume soak test (default 6,000 requests across `gather()` and native Tokio `AsyncSession` tracking throughput, Python heap, and OS RSS):

```bash
python benchmarks/soak_test.py --requests 3000 --concurrency 50
```

Run the live throughput and memory benchmark against `curl_cffi`:

```bash
python benchmarks/bench_vs_competitors.py --url https://www.cloudflare.com/cdn-cgi/trace --n 15 --concurrency 30
```

Run the pure Rust HTML5 / CSS3 / XPath / JSON / Regex extraction benchmark:

```bash
python benchmarks/bench_extraction.py --cards 500 --runs 30
```

See [CHANGELOG.md](CHANGELOG.md) for the complete version history.

---

## License

Released under the [MIT License](LICENSE).
