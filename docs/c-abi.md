# C-ABI Shared Library (`http_tls.dll` / `libhttp_tls.so` / `libhttp_tls.dylib`)

Use `http_tls` natively from **C# (.NET)**, **Go**, **Node.js**, **C/C++**, **PHP**, **AutoIt**, **Rust**, or any language with C FFI — **zero Python installation required** (`python3.dll` is never linked).

---

## 1. Download & Platform Requirements

Pre-built binaries and [`http_tls.h`](../include/http_tls.h) are attached to every [GitHub Release](https://github.com/real-coder-xD/http_tls/releases):

| Platform | Release Asset | System Runtime Requirement |
| :--- | :--- | :--- |
| Windows `x86_64` | `http_tls-windows-x86_64.dll` (+ `.dll.lib`) | Windows 10/11 / Server 2016+ (standard MSVC C++ Redistributable — already present on 99% of machines) |
| Linux `x86_64` | `libhttp_tls-linux-x86_64.so` | `glibc >= 2.28` (Ubuntu 20.04+, Debian 11+, RHEL/Alma 8+, Docker slim) |
| Linux `aarch64` | `libhttp_tls-linux-aarch64.so` | `glibc >= 2.28` (ARM64 servers, AWS Graviton, Raspberry Pi 64-bit) |
| macOS Apple Silicon | `libhttp_tls-macos-aarch64.dylib` | macOS 11+ |
| macOS Intel | `libhttp_tls-macos-x86_64.dylib` | macOS 11+ |
| C / C++ Header | `http_tls.h` | C99 / C++11+ |

> Rename the downloaded file to `http_tls.dll` (Windows), `libhttp_tls.so` (Linux), or `libhttp_tls.dylib` (macOS) and place it next to your executable or on your library search path.

---

## 2. Memory & Threading Contract (Read First)

1. **UTF-8 JSON in, UTF-8 JSON out:** Every function accepts NUL-terminated UTF-8 JSON strings and returns a heap-allocated NUL-terminated UTF-8 JSON `char*`.
2. **Always free returned pointers:** Call `http_tls_free_string(ptr)` once for every non-NULL `char*` returned by any `http_tls_*` function. Passing `NULL` is a safe no-op.
3. **100% thread-safe & full-duplex:**
   - Multiple OS threads can call `http_tls_request` / `http_tls_gather` concurrently on the **same `session_id`**.
   - WebSockets are **true full-duplex**: Thread A can block in `http_tls_ws_recv` while Thread B calls `http_tls_ws_send` with zero lock contention.
   - Calling `http_tls_ws_close` or `http_tls_stream_close` from another thread **instantly cancels** a blocked `ws_recv` / `stream_read`.
4. **No cross-FFI panics:** Every entrypoint is guarded with `catch_unwind`; malformed JSON, invalid UTF-8, NULL pointers, or network failures always return `{"ok": false, "error": "...", "error_kind": "..."}`.
5. **Clean shutdown:** Call `http_tls_destroy_session` / `http_tls_stream_close` / `http_tls_ws_close` when finished (or `http_tls_destroy_all_sessions()` on process exit).

---

## 3. Complete C-ABI Reference (19 Functions)

Header file: [`include/http_tls.h`](../include/http_tls.h)

| Group | Function | Input | Output |
| :--- | :--- | :--- | :--- |
| **Meta** | `http_tls_version()` | `void` | `{"ok": true, "version": "...", "presets_count": 131, "features": [...]}` |
| | `http_tls_presets()` | `void` | `{"ok": true, "count": 131, "presets": ["chrome_149", ...]}` |
| **Sessions** | `http_tls_create_session(cfg_json)` | `NULL`, `"{}"`, or session config JSON | `{"ok": true, "session_id": "s-...", "impersonate": "chrome_149"}` |
| | `http_tls_set_impersonate(json)` | `{"session_id": "...", "impersonate": "firefox_151"}` | `{"ok": true, "session_id": "...", "impersonate": "firefox_151"}` |
| | `http_tls_destroy_session(id_or_json)` | `"s-..."` or `{"session_id": "s-..."}` | `{"ok": true, "session_id": "...", "destroyed": true}` |
| | `http_tls_destroy_all_sessions()` | `void` | `{"ok": true, "destroyed_count": N, "destroyed_streams": M, "destroyed_websockets": K}` |
| **HTTP** | `http_tls_request(req_json)` | Request JSON (with or without `session_id`) | Full response JSON (`status_code`, `http_version`, `headers`, `cookies`, `body`, `ech_accepted`, `challenge`, ...) |
| | `http_tls_gather(req_json)` | `{"session_id": "...", "concurrency": 50, "requests": [...]}` | `{"ok": true, "count": N, "responses": [...]}` (exact input order) |
| **Cookies** | `http_tls_get_cookies(json)` | `{"session_id": "..."}` or `{"session_id": "...", "url": "..."}` | `{"ok": true, "cookies": [...]}` (all) or `{"ok": true, "cookies": {"k": "v"}}` (URL-filtered) |
| | `http_tls_set_cookies(json)` | `clear`, `delete_name`, `raw_cookie`+`url`, `cookies` array or `{k:v}` map | `{"ok": true, "session_id": "...", "count": N}` |
| **Streaming** | `http_tls_stream_open(req_json)` | Same schema as `http_tls_request` | `{"ok": true, "stream_id": "st-...", "status_code": 200, "http_version": "...", "headers": {...}}` |
| | `http_tls_stream_read(id_or_json)` | `"st-..."` or `{"stream_id": "st-...", "timeout": 30.0}` | `{"ok": true, "eof": false, "length": N, "text": "...", "data_base64": "..."}` (auto-closes on `eof: true`) |
| | `http_tls_stream_close(id_or_json)` | `"st-..."` or `{"stream_id": "st-..."}` | `{"ok": true, "stream_id": "...", "closed": true}` |
| **WebSocket** | `http_tls_ws_connect(json)` | `{"url": "wss://...", "session_id": "...", "impersonate": "...", "headers": {...}, "proxy": "..."}` | `{"ok": true, "ws_id": "ws-...", "status_code": 101, "headers": {...}, "protocol": ...}` |
| | `http_tls_ws_send(json)` | `{"ws_id": "ws-...", "text" \| "data_base64" \| "ping_base64": "..."}` | `{"ok": true, "ws_id": "..."}` |
| | `http_tls_ws_recv(id_or_json)` | `"ws-..."` or `{"ws_id": "ws-...", "timeout": 30.0}` | `{"ok": true, "closed": false, "kind": "text"\|"binary"\|"ping"\|"pong"\|"close", "text": ..., "data_base64": ...}` |
| | `http_tls_ws_close(id_or_json)` | `"ws-..."` or `{"ws_id": "ws-...", "code": 1000, "reason": ""}` | `{"ok": true, "ws_id": "...", "closed": true}` |
| **Extraction** | `http_tls_extract(json)` | `{"content": "...", "css"\|"xpath"\|"json_path"\|"regex": "...", "first": false}` or `left`+`right` | `{"ok": true, "mode": "...", "result": ...}` |
| **Memory** | `http_tls_free_string(ptr)` | `char*` returned by any `http_tls_*` call | `void` |

---

## 4. JSON Schemas & Recipes

### 4.1 Session Configuration (`http_tls_create_session`)

All fields are optional; defaults use `impersonate: "chrome_149"` and `timeout: 30.0`.

```json
{
  "session_id": "optional-custom-id",
  "impersonate": "chrome_149",
  "timeout": 30.0,
  "connect_timeout": 10.0,
  "read_timeout": 20.0,
  "follow_redirects": true,
  "max_redirects": 10,
  "verify": true,
  "proxy": "socks5h://user:pass@127.0.0.1:1080",
  "headers": {
    "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8"
  },
  "header_order": ["host", "user-agent", "accept", "accept-language"],
  "http3": true,
  "http3_only": false,
  "http2_only": false,
  "http1_only": false,
  "ech": true,
  "doh": true,
  "doh_url": "https://cloudflare-dns.com/dns-query",
  "ja3": "771,4865-4866-4867-49195-49199,0-23-65281,4588-29-23-24,0",
  "akamai_h2": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
  "resolve": { "api.example.com": "127.0.0.1" },
  "local_address": "192.168.1.50",
  "ca_bundle_path": "/path/to/ca.pem",
  "client_cert_path": "/path/to/client.pem",
  "client_key_path": "/path/to/client.key",
  "tls_info": false,
  "keylog_file": "/tmp/sslkeys.log"
}
```

### 4.2 Request Options (`http_tls_request`)

You may pass `"session_id"` (reuses cookies, H2/H3 pools, ECH & TLS 1.3 ticket caches) **or omit `"session_id"`** for a one-shot call that accepts all session fields inline.

```json
{
  "session_id": "s-1-abcd1234",
  "method": "POST",
  "url": "https://api.example.com/v1/submit",
  "params": { "lang": "vi" },
  "headers": { "Authorization": "Bearer token" },
  "cookies": { "csrf": "xyz" },
  "json": { "item": 42 },
  "timeout": 15.0,
  "allow_redirects": true,
  "return_body_base64": false
}
```

**Body modes** (pick one):
- `"json"`: JSON object/array/primitive or raw JSON string (automatically sets `Content-Type: application/json` unless you provide a custom `Content-Type` header).
- `"form"`: `{"user": "alice", "pass": "123"}` (automatically URL-encodes and sets `Content-Type: application/x-www-form-urlencoded`).
- `"body"` (or `"data"`): raw UTF-8 string.
- `"body_base64"`: Base64-encoded binary bytes.
- `"files"`: multipart upload array:
  ```json
  "files": [
    {
      "field": "avatar",
      "filename": "photo.png",
      "content_base64": "iVBORw0KGgo...",
      "content_type": "image/png"
    }
  ]
  ```
  *(Each entry accepts `"content_base64"`, `"content"` string, or `"path"` to a local file.)*

### 4.3 Response JSON

```json
{
  "ok": true,
  "status_code": 200,
  "url": "https://cloudflare-ech.com/cdn-cgi/trace",
  "http_version": "HTTP/3",
  "headers": { "content-type": "text/plain" },
  "cookies": { "sid": "abc" },
  "body": "fl=...\nsni=encrypted\n...",
  "body_base64": null,
  "content_length": 284,
  "encoding": "utf-8",
  "elapsed": 0.142,
  "remote_addr": "104.18.10.118:443",
  "ech_accepted": true,
  "tls_resumed": false,
  "challenge": null,
  "history": [],
  "peer_certificate_base64": null
}
```

- `body_base64` is populated automatically whenever `return_body_base64: true` **or** the response contains non-UTF-8 binary bytes (images, PDFs, protobuf, etc.).
- `challenge` automatically flags anti-bot interstitials: `"cloudflare"`, `"datadome"`, `"akamai"`, `"ddos-guard"`, `"perimeterx"`, `"imperva"`, `"sucuri"`, `"vercel"`, or `null`.

### 4.4 Concurrent Batching (`http_tls_gather`)

Runs all requests concurrently on the Rust Tokio thread pool and returns results in **exact input order**. Individual request errors appear as `{"ok": false, ...}` inside `responses[i]` without failing the rest of the batch.

```json
{
  "session_id": "s-1-abcd1234",
  "concurrency": 50,
  "requests": [
    { "url": "https://example.com/page/1" },
    { "url": "https://example.com/page/2" },
    { "method": "POST", "url": "https://example.com/api", "json": { "id": 3 } }
  ]
}
```

### 4.5 Cookie Management (`http_tls_get_cookies` / `http_tls_set_cookies`)

Three supported ways to inject cookies into a session:

```json
// 1. Simple {name: value} map scoped to a URL
{ "session_id": "s-1", "url": "https://example.com/", "cookies": { "cf_clearance": "abc", "sid": "123" } }

// 2. Full cookie array (inherits host from top-level `url` if `domain` is omitted)
{ "session_id": "s-1", "clear": true, "cookies": [
    { "name": "cf_clearance", "value": "abc", "domain": "example.com", "path": "/", "secure": true, "http_only": true }
]}

// 3. Raw Set-Cookie header string
{ "session_id": "s-1", "url": "https://example.com/", "raw_cookie": "sid=xyz; Path=/; Secure" }

// 4. Delete a single cookie by name (optional domain/path filter)
{ "session_id": "s-1", "delete_name": "sid", "domain": "example.com" }
```

### 4.6 Incremental Streaming (`http_tls_stream_*`)

Ideal for large file downloads and Server-Sent Events (SSE / AI streaming):

1. Open: `http_tls_stream_open({"url": "https://...", "http3": true, "ech": true})` -> read `stream_id`, `status_code`, `headers`.
2. Loop: `http_tls_stream_read({"stream_id": st_id, "timeout": 30.0})` until `"eof": true`.
   - For binary files or multi-byte UTF-8 streams, decode and concatenate `"data_base64"` bytes so multi-byte characters split across TCP/QUIC packets never corrupt.
3. Cancel early (optional, thread-safe): `http_tls_stream_close(st_id)` immediately cancels any blocked `stream_read` in another thread.

### 4.7 Full-Duplex WebSockets (`http_tls_ws_*`)

1. Connect: `http_tls_ws_connect({"url": "wss://stream.example.com/ws", "impersonate": "chrome_149"})` -> `ws_id`.
2. Send (any thread): `http_tls_ws_send({"ws_id": ws_id, "text": "{\"op\":\"sub\"}"})` or `"data_base64"` for binary.
3. Receive (any thread, concurrent with send): `http_tls_ws_recv({"ws_id": ws_id, "timeout": 30.0})`. A `"timeout"` error leaves the socket open and healthy.
4. Close (any thread): `http_tls_ws_close({"ws_id": ws_id, "code": 1000, "reason": "bye"})`.

### 4.8 Pure Rust Extraction (`http_tls_extract`)

```json
// HTML5 CSS3 (supports :has(), :contains(), ::text, ::attr(name), comma lists)
{ "html": "<h1>Title</h1><a href='/p/1'>Buy</a>", "css": "h1::text, a::attr(href)" }

// Native Rust XPath 1.0
{ "html": "<div class='card'><span>$19.99</span></div>", "xpath": "//div[@class='card']/span/text()", "first": true }

// JSONPath (dot paths, negative indices, slices, wildcards [*], recursive $..key, filters [?(@.x > 1)])
{ "content": "{\"items\":[{\"name\":\"A\",\"price\":10},{\"name\":\"B\",\"price\":35}]}", "json_path": "items[?(@.price > 20)].name" }

// Linear-time DFA Regex (returns capture group 1 if present)
{ "content": "Price: $19.99 and $49.50", "regex": "\\$([0-9]+\\.[0-9]+)" }

// Delimiter slicing (UTF-8 safe)
{ "content": "id=101;id=202;", "left": "id=", "right": ";", "first": false }
```

### 4.9 Error Format & `error_kind` Codes

Every failure returns `{"ok": false, "error": "human-readable detail", "error_kind": "..."}`:

| `error_kind` | Meaning |
| :--- | :--- |
| `value` | Invalid JSON, invalid UTF-8, bad URL/proxy/JA3/Akamai/selector, out-of-range integer |
| `connect` | DNS failure, connection refused, proxy connect failure, socket reset |
| `connect_timeout` | TCP / QUIC handshake timed out |
| `timeout` | Request, stream read, or WebSocket send/recv timed out |
| `ssl` | TLS handshake or certificate verification error |
| `redirect` | Exceeded `max_redirects` |
| `request` | General HTTP/WebSocket protocol error |
| `session_not_found` / `stream_not_found` / `ws_not_found` | Unknown or already-closed handle ID |
| `panic` | Internal panic safely caught before unwinding across FFI |

---

## 5. Runnable Language Examples

Complete projects live under [`ffi/examples/`](../ffi/examples/):

- **C# (.NET 8+ P/Invoke):** [`ffi/examples/csharp/Program.cs`](../ffi/examples/csharp/Program.cs)
- **Go (Zero-CGO Windows DLL):** [`ffi/examples/go/main.go`](../ffi/examples/go/main.go)
- **Node.js (`koffi` Windows/Linux/macOS):** [`ffi/examples/nodejs/example.mjs`](../ffi/examples/nodejs/example.mjs)
- **C / C++ Header:** [`include/http_tls.h`](../include/http_tls.h)

### PHP 8.1+ (Built-in FFI, zero Composer deps)

```php
<?php
$ffi = FFI::cdef("
    char* http_tls_request(const char* request_json);
    void  http_tls_free_string(char* ptr);
", __DIR__ . "/http_tls.dll"); // or libhttp_tls.so / libhttp_tls.dylib

$payload = json_encode([
    "url"         => "https://cloudflare-ech.com/cdn-cgi/trace",
    "impersonate" => "chrome_149",
    "http3"       => true,
    "ech"         => true,
    "doh"         => true,
]);

$ptr = $ffi->http_tls_request($payload);
try {
    $resp = json_decode(FFI::string($ptr), true);
    echo "{$resp['http_version']} {$resp['status_code']} | ech_accepted=" . ($resp['ech_accepted'] ? 'true' : 'false') . "\n";
} finally {
    $ffi->http_tls_free_string($ptr);
}
```

### C / C++ Minimal Example

```c
#include <stdio.h>
#include "http_tls.h"

int main(void) {
    char* resp = http_tls_request(
        "{\"url\":\"https://cloudflare-ech.com/cdn-cgi/trace\","
        "\"impersonate\":\"chrome_149\",\"http3\":true,\"ech\":true,\"doh\":true}"
    );
    if (resp) {
        puts(resp);
        http_tls_free_string(resp);
    }
    return 0;
}
```

Compile on Windows (MSVC):
```powershell
cl /W4 /I include main.c /link target\release\http_tls.dll.lib
```

Compile on Linux / macOS:
```bash
cc -O2 -I include main.c -L target/release -lhttp_tls -Wl,-rpath,'$ORIGIN' -o main
```

---

## 6. Writing a Binding / Wrapper for Any Other Language

Want to publish a wrapper for **Java / Kotlin (Panama FFM / JNA)**, **Ruby (`Fiddle`)**, **Dart / Flutter (`dart:ffi`)**, **Swift**, **Zig**, **AutoIt**, **Delphi**, or **PowerShell**? Every binding follows the exact same 5-step blueprint:

1. **Load the native library** with the standard C calling convention (`cdecl`): `http_tls.dll` (Windows), `libhttp_tls.so` (Linux), or `libhttp_tls.dylib` (macOS).
2. **Bind pointers as opaque `void*` (not auto-freed string types):** Map every returning `http_tls_*` function as returning a raw pointer (`IntPtr` / `void*` / `uintptr`), because your language runtime must **not** call its own `free()` on memory allocated by Rust.
3. **Write one `consume(ptr)` helper** used by every call:
   - Check `ptr != NULL`.
   - Read NUL-terminated UTF-8 bytes from `ptr` and decode JSON.
   - Always call `http_tls_free_string(ptr)` inside `finally` / `defer` / RAII destructor.
4. **Wrap handle lifecycles cleanly:**
   - `Session` object -> stores `session_id`, calls `http_tls_destroy_session(session_id)` on `Dispose` / `close()` / `Drop`.
   - `Stream` object -> stores `stream_id`, calls `http_tls_stream_close(stream_id)` on early exit (auto-closed on `eof: true`).
   - `WebSocket` object -> stores `ws_id`, safe to read and write from separate threads simultaneously; calls `http_tls_ws_close(ws_id)` on close.
5. **Smoke-test against the live contract:** Call `http_tls_version()` (`ok == true`), send a `http3: true, ech: true, doh: true` request to `https://cloudflare-ech.com/cdn-cgi/trace`, verify `ech_accepted == true`, and check `http_tls_extract` returns valid UTF-8.

---

## 7. Building From Source

Requires Rust stable (`rustup`), CMake, Clang/LLVM, Perl, and NASM (on Windows for BoringSSL assembly):

```bash
cargo build --release --manifest-path ffi/Cargo.toml --target-dir target
```

Artifacts produced in `target/release/`:
- Windows: `http_tls.dll`, `http_tls.dll.lib`
- Linux: `libhttp_tls.so`
- macOS: `libhttp_tls.dylib`

Verify zero Python linkage and run the FFI test suite:

```bash
# Linux
! ldd target/release/libhttp_tls.so | grep -i python
# macOS
! otool -L target/release/libhttp_tls.dylib | grep -i python
# Run automated C-ABI test suite
pytest -v tests/test_ffi_capi.py
```
