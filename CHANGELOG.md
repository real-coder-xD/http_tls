# Changelog

All notable changes to `http_tls` are documented in this file.

## [0.5.0] - 2026-11-21

### Added
- **Standalone Rust + BoringSSL Core (`wreq 0.16` + `btls` + `wreq-util 0.2`):** Byte-exact Chrome/Edge/Safari/Firefox/Opera/OkHttp JA3, JA4, GREASE, ALPS, Post-Quantum `X25519MLKEM768`, and Akamai HTTP/2 `SETTINGS` / pseudo-header ordering (`m,a,s,p`) baked directly into the ABI3 wheel (~3.75 MB) with zero external C runtime dependencies.
- **Native Tokio Async (`pyo3-async-runtimes`):** `AsyncSession` / `AsyncClient` maps Rust Tokio futures directly onto Python's `asyncio` event loop without `asyncio.to_thread` thread-pool bottlenecks.
- **Exact Wire Header Order (`header_order`):** Preserves exact header casing and wire order via `OrigHeaderMap` at session and per-request levels.
- **Custom TLS / JA3 / HTTP/2 Configuration:** `ja3=` string translator, `tls_options=` (`cipher_list`, `curves_list`, `sigalgs_list`, `alpn`, `min_tls_version`, `max_tls_version`, `grease_enabled`, `permute_extensions`, `enable_ech_grease`, `enable_ocsp_stapling`), `http2_options=`, `http1_only`, `http2_only`.
- **DNS Override & Socket Binding:** `resolve={"domain": "ip"}` for custom DNS / origin IP routing with preserved SNI/Host, plus `local_address` (IPv4/IPv6 `/64` rotation) and `interface` binding.
- **TLS-Impersonated WebSockets:** Sync `session.ws_connect(...)` and native async `await async_session.ws_connect(...)`.
- **Multipart File Uploads:** Full `files=` support compatible with `requests` and `httpx`.
- **Resilience & Anti-Bot Automation:** `retries`, `retry_backoff` (exponential + jitter), `retry_statuses`, `retry_on_challenge`, `rotate_impersonate`, `proxies_pool` round-robin rotation.
- **Full `httpx` / `requests` Parity:** `base_url`, `resp.history`, `resp.http_version`, `resp.remote_addr`, `resp.peer_certificate` (`tls_info=True`), `DigestAuth` (RFC 7616 MD5/SHA-256/SHA-512), `BearerAuth`, `BasicAuth`, sync & async `event_hooks`, `aiter_bytes()`, `aiter_lines()`, `aread()`.
- **Automated Quality & Regression CI:** `pytest` suite (including compression, 307/308 redirect preservation, proxy rotation, 300-concurrency memory stress test, live JA4 verification), `cargo clippy` gate, multi-Python ABI3 verification, and scheduled weekly WAF regression workflow.

## [0.3.2] - 2026-11-18
- Repackaged `v0.3.1` with updated `README.md` feature matrix and `httpx` drop-in documentation on PyPI.

## [0.3.1] - 2026-11-18
- Deep `session.cookies.clear()` synchronization across Python and native cookie jars.
- `httpx`-compatible aliases (`Client`, `AsyncClient`, `is_success`, `is_error`, `is_client_error`, `is_server_error`, `read()`, `aread()`).

## [0.3.0] - 2026-11-17
- Shared process-wide Tokio runtime, streaming responses (`stream=True`, `iter_content`, `iter_lines`), custom CA bundles (`verify=path`), mTLS (`cert=`), `resp.challenge` WAF detector, and `requests`-style exception mapping.

## [0.2.1] - 2026-11-15
- Initial PyPI Trusted Publisher release with multi-platform ABI3 wheels.
