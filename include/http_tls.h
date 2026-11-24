/*
 * http_tls C-ABI Header (http_tls.dll / libhttp_tls.so / libhttp_tls.dylib)
 *
 * Standalone Rust + Pure BoringSSL HTTP/1.1, HTTP/2 & UDP QUIC HTTP/3 client
 * with Real ECH, DNS-over-HTTPS, SOCKS5 UDP, JA3/Akamai H2, concurrent gather,
 * WAF challenge detection, and Pure Rust HTML5 CSS3 / XPath / JSONPath / Regex extraction.
 *
 * Memory contract:
 *   Every non-NULL `char*` returned by `http_tls_*` is a heap-allocated UTF-8 JSON string.
 *   Callers MUST release every returned pointer with `http_tls_free_string(ptr)`.
 *   Passing NULL to `http_tls_free_string` is a safe no-op.
 *
 * Thread safety:
 *   All functions are thread-safe and may be called concurrently from multiple OS threads,
 *   including concurrent requests sharing the same `session_id`.
 */

#ifndef HTTP_TLS_H
#define HTTP_TLS_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
  #define HTTP_TLS_API __declspec(dllimport)
#else
  #define HTTP_TLS_API
#endif

/** Return engine version, preset count, and supported features as JSON. */
HTTP_TLS_API char* http_tls_version(void);

/** Return all 100+ supported browser impersonation presets as JSON. */
HTTP_TLS_API char* http_tls_presets(void);

/**
 * Create a persistent session (Cookie Jar, HTTP/2 & HTTP/3 pools, ECH & TLS 1.3 ticket caches).
 * `config_json` may be NULL or "{}" for defaults (`impersonate: "chrome_149"`).
 * Returns: {"ok": true, "session_id": "...", "impersonate": "..."}
 */
HTTP_TLS_API char* http_tls_create_session(const char* config_json);

/**
 * Execute an HTTP/1.1, HTTP/2, or UDP QUIC HTTP/3 request.
 * If `session_id` is omitted, executes using a one-shot session with any config fields in `request_json`.
 * Returns: {"ok": true, "status_code": 200, "http_version": "HTTP/3", "headers": {...},
 *           "cookies": {...}, "body": "...", "ech_accepted": true, "tls_resumed": false,
 *           "challenge": null, ...}
 */
HTTP_TLS_API char* http_tls_request(const char* request_json);

/**
 * Execute a batch of requests concurrently on the Rust Tokio thread pool.
 * Input: {"session_id": "...", "concurrency": 50, "requests": [ { "url": "..." }, ... ]}
 * Returns responses in exact input order: {"ok": true, "count": N, "responses": [...]}
 */
HTTP_TLS_API char* http_tls_gather(const char* request_json);

/**
 * Read cookies from a session.
 * Input: {"session_id": "..."} (all cookies) or {"session_id": "...", "url": "https://..."}
 */
HTTP_TLS_API char* http_tls_get_cookies(const char* request_json);

/**
 * Set, inject, delete, or clear cookies on a session.
 * Input: {"session_id": "...", "clear": false, "cookies": [{"name":"k","value":"v","domain":"example.com"}]}
 *        or {"session_id": "...", "raw_cookie": "k=v; Path=/", "url": "https://example.com/"}
 */
HTTP_TLS_API char* http_tls_set_cookies(const char* request_json);

/**
 * Hot-swap the active browser impersonation profile of an existing session.
 * Input: {"session_id": "...", "impersonate": "firefox_151"}
 */
HTTP_TLS_API char* http_tls_set_impersonate(const char* request_json);

/**
 * Close connection pools and free a session.
 * Accepts either a raw session ID string ("s-1-abcd1234") or {"session_id": "..."}.
 */
HTTP_TLS_API char* http_tls_destroy_session(const char* session_id);

/** Close and free all active sessions, open streams, and open WebSockets. */
HTTP_TLS_API char* http_tls_destroy_all_sessions(void);

/**
 * Open an incremental streaming HTTP/1.1, HTTP/2, or HTTP/3 response (zero whole-body buffering).
 * Returns: {"ok": true, "stream_id": "st-...", "status_code": 200, "http_version": "...", "headers": {...}}
 */
HTTP_TLS_API char* http_tls_stream_open(const char* request_json);

/**
 * Read the next chunk from an open stream.
 * Accepts raw stream_id ("st-...") or {"stream_id": "...", "timeout": 30.0}.
 * Returns: {"ok": true, "eof": false, "length": N, "text": "...", "data_base64": "..."}
 * Auto-closes and removes the handle once `eof` is true.
 */
HTTP_TLS_API char* http_tls_stream_read(const char* request_json);

/** Close an open stream early and release its handle. */
HTTP_TLS_API char* http_tls_stream_close(const char* stream_id);

/**
 * Connect a TLS-impersonated WebSocket (`ws://` or `wss://`).
 * Input: {"url": "wss://...", "session_id": "...", "impersonate": "chrome_149", "headers": {...}, "proxy": "..."}
 * Returns: {"ok": true, "ws_id": "ws-...", "status_code": 101, "headers": {...}, "protocol": ...}
 */
HTTP_TLS_API char* http_tls_ws_connect(const char* request_json);

/**
 * Send a WebSocket frame (`text`, `data_base64`, or `ping_base64`).
 * Input: {"ws_id": "ws-...", "text": "hello"} or {"ws_id": "ws-...", "data_base64": "..."}
 */
HTTP_TLS_API char* http_tls_ws_send(const char* request_json);

/**
 * Receive the next WebSocket frame.
 * Accepts raw ws_id ("ws-...") or {"ws_id": "...", "timeout": 30.0}.
 * Returns: {"ok": true, "closed": false, "kind": "text"|"binary"|"ping"|"pong", "text": ..., "data_base64": ...}
 */
HTTP_TLS_API char* http_tls_ws_recv(const char* request_json);

/**
 * Gracefully close a WebSocket and free its handle.
 * Accepts raw ws_id ("ws-...") or {"ws_id": "...", "code": 1000, "reason": ""}.
 */
HTTP_TLS_API char* http_tls_ws_close(const char* request_json);

/**
 * Pure Rust extraction engine (HTML5 CSS3, XPath 1.0, JSONPath, DFA Regex, between/between_all).
 * Input: {"content": "...", "css"|"xpath"|"json_path"|"regex": "...", "first": false}
 *        or {"content": "...", "left": "...", "right": "...", "first": false}
 */
HTTP_TLS_API char* http_tls_extract(const char* request_json);

/** Free any UTF-8 JSON string returned by `http_tls_*`. */
HTTP_TLS_API void http_tls_free_string(char* ptr);

#ifdef __cplusplus
}
#endif

#endif /* HTTP_TLS_H */
