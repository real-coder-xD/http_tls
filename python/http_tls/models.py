"""Drop-in compatibility module matching requests, httpx, and curl_cffi APIs.

Powered by the standalone Rust BoringSSL (`wreq` + `btls` + Tokio) engine:
- Byte-exact JA3/JA4/HTTP2 emulation (100+ presets + custom JA3 / TLS / H2 options)
- Exact wire header casing & order (`header_order` / OrigHeaderMap)
- Custom DNS / Origin IP (`resolve`), IPv4/IPv6 binding (`local_address`, `interface`)
- True native Tokio async (`pyo3-async-runtimes`), streaming, multipart uploads, WebSockets
- Auto-retry with backoff + proxy pool + preset rotation on anti-bot challenges
- `base_url`, `resp.history`, `resp.remote_addr`, `resp.peer_certificate`, `DigestAuth`, `event_hooks`
"""

from __future__ import annotations

import asyncio
import codecs
from contextlib import asynccontextmanager, contextmanager
import datetime as _dt
from enum import Enum
import inspect
import json as _json
import os
import random as _random
import re
import threading as _threading
import time as _time
from typing import Any, AsyncIterator, Callable, Dict, Iterator, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlencode, urljoin, urlparse

from http_tls import challenge as _challenge
from http_tls.auth import AuthBase, BasicAuth, BearerAuth, DigestAuth
from http_tls.exceptions import (
    ConnectTimeout,
    ConnectionError,
    HTTPError,
    ReadTimeout,
    RequestException,
    SSLError,
    Timeout,
    TooManyRedirects,
)
from http_tls.solvers import infer_impersonate_from_user_agent, run_coroutine_sync
from http_tls.status_codes import codes
from http_tls.structures import CaseInsensitiveDict

# Native Rust BoringSSL engine
try:
    from http_tls._core import (
        Element,
        HtmlDocument,
        JsonDocument,
        Session as _RustSession,
        WebSocket as _NativeWebSocket,
        __version__,
        extract_between as _rust_extract_between,
        extract_between_all as _rust_extract_between_all,
        extract_json_path as _rust_extract_json_path,
        extract_re as _rust_extract_re,
        extract_re_first as _rust_extract_re_first,
        is_verified_preset as _rust_is_verified_preset,
        parse_html as _rust_parse_html,
        parse_json as _rust_parse_json,
        supported_presets as _rust_presets,
    )
except ImportError:
    Element = Any  # type: ignore[misc, assignment]
    HtmlDocument = Any  # type: ignore[misc, assignment]
    JsonDocument = Any  # type: ignore[misc, assignment]
    _RustSession = None
    _NativeWebSocket = None
    __version__ = "1.2.0"
    _rust_parse_html = None
    _rust_parse_json = None
    _rust_extract_re = None
    _rust_extract_re_first = None
    _rust_extract_between = None
    _rust_extract_between_all = None
    _rust_extract_json_path = None

    def _rust_presets() -> List[str]:
        return []

    def _rust_is_verified_preset(preset: str) -> bool:
        return False


# Optional legacy curl_cffi backend (only used when explicitly requested via engine="curl_cffi")
_CffiSession: Optional[Callable[..., Any]] = None
try:
    import curl_cffi.requests.session as _cffi_mod
    _CffiSession = getattr(_cffi_mod, "Session", None)
    _HAS_CFFI = _CffiSession is not None
except ImportError:
    _HAS_CFFI = False


class BrowserType(str, Enum):
    """Verified native browser presets (strictly real released profiles, zero extrapolated future versions)."""
    chrome149 = "chrome_149"
    chrome149_macos = "chrome_149_macos"
    chrome148 = "chrome_148"
    chrome147 = "chrome_147"
    chrome146 = "chrome_146"
    chrome145 = "chrome_145"
    chrome144 = "chrome_144"
    chrome143 = "chrome_143"
    chrome142 = "chrome_142"
    chrome141 = "chrome_141"
    chrome140 = "chrome_140"
    chrome139 = "chrome_139"
    chrome138 = "chrome_138"
    chrome137 = "chrome_137"
    chrome136 = "chrome_136"
    chrome135 = "chrome_135"
    chrome134 = "chrome_134"
    chrome133 = "chrome_133"
    chrome132 = "chrome_132"
    chrome131 = "chrome_131"
    chrome131_android = "chrome_131_android"
    chrome130 = "chrome_130"
    chrome129 = "chrome_129"
    chrome128 = "chrome_128"
    chrome127 = "chrome_127"
    chrome126 = "chrome_126"
    chrome124 = "chrome_124"
    chrome123 = "chrome_123"
    chrome120 = "chrome_120"
    chrome119 = "chrome_119"
    chrome116 = "chrome_116"
    chrome114 = "chrome_114"
    chrome110 = "chrome_110"
    chrome107 = "chrome_107"
    chrome104 = "chrome_104"
    chrome100 = "chrome_100"
    edge148 = "edge_148"
    edge147 = "edge_147"
    edge146 = "edge_146"
    edge145 = "edge_145"
    edge142 = "edge_142"
    edge136 = "edge_136"
    edge134 = "edge_134"
    edge131 = "edge_131"
    edge127 = "edge_127"
    edge122 = "edge_122"
    edge101 = "edge_101"
    safari26_4 = "safari_26_4"
    safari26_3 = "safari_26_3"
    safari26_2 = "safari_26_2"
    safari26_1 = "safari_26_1"
    safari26 = "safari_26"
    safari_ios_26_2 = "safari_ios_26_2"
    safari_ios_26 = "safari_ios_26"
    safari18_5 = "safari_18_5"
    safari184 = "safari_18_4"
    safari180 = "safari_18"
    safari18 = "safari_18"
    safari170 = "safari_17_0"
    safari17 = "safari_17_0"
    safari155 = "safari_15_5"
    firefox151 = "firefox_151"
    firefox150 = "firefox_150"
    firefox149 = "firefox_149"
    firefox148 = "firefox_148"
    firefox147 = "firefox_147"
    firefox146 = "firefox_146"
    firefox145 = "firefox_145"
    firefox144 = "firefox_144"
    firefox143 = "firefox_143"
    firefox142 = "firefox_142"
    firefox139 = "firefox_139"
    firefox136 = "firefox_136"
    firefox135 = "firefox_135"
    firefox133 = "firefox_133"
    firefox128 = "firefox_128"
    firefox117 = "firefox_117"
    firefox109 = "firefox_109"
    opera131 = "opera_131"
    opera130 = "opera_130"
    opera128 = "opera_128"
    opera124 = "opera_124"
    opera120 = "opera_120"
    opera116 = "opera_116"
    okhttp5 = "okhttp_5"
    okhttp4_12 = "okhttp_4_12"
    okhttp4_10 = "okhttp_4_10"
    tor145 = "tor_14_5"
    random = "random"
    weighted_random = "weighted_random"

    def __str__(self) -> str:
        return self.value


STABLE_PRESETS: Tuple[str, ...] = tuple(
    _rust_presets() or [b.value for b in BrowserType if b.value not in ("random", "weighted_random")]
)


def supported_presets() -> List[str]:
    """Return all verified native BoringSSL + HTTP/2 browser profiles (zero header extrapolation)."""
    return list(_rust_presets()) or [b.value for b in BrowserType]


def is_verified_preset(preset: Union[str, BrowserType]) -> bool:
    """Return True if `preset` resolves to a native byte-exact BoringSSL/H2 profile without header extrapolation."""
    return bool(_rust_is_verified_preset(str(preset)))


class TimeoutConfig:
    """Granular timeout configuration (`httpx.Timeout`-compatible without colliding with `http_tls.Timeout` exception)."""

    def __init__(
        self,
        timeout: Optional[float] = 30.0,
        *,
        connect: Optional[float] = None,
        read: Optional[float] = None,
        write: Optional[float] = None,
        pool: Optional[float] = None,
    ) -> None:
        self.timeout = timeout
        self.connect = connect if connect is not None else timeout
        self.read = read if read is not None else timeout
        self.write = write if write is not None else timeout
        self.pool = pool if pool is not None else timeout

    def total(self) -> float:
        vals = [v for v in (self.timeout, self.read, self.connect) if v is not None]
        return float(max(vals)) if vals else 30.0

    def __repr__(self) -> str:
        return (
            f"TimeoutConfig(timeout={self.timeout!r}, connect={self.connect!r}, "
            f"read={self.read!r}, write={self.write!r}, pool={self.pool!r})"
        )


class Limits:
    """Connection pool limits (`httpx.Limits`-compatible) mapped directly to Rust connection pooling."""

    def __init__(
        self,
        max_connections: Optional[int] = None,
        max_keepalive_connections: Optional[int] = None,
        keepalive_expiry: Optional[float] = 5.0,
    ) -> None:
        self.max_connections = max_connections
        self.max_keepalive_connections = max_keepalive_connections
        self.keepalive_expiry = keepalive_expiry

    def __repr__(self) -> str:
        return (
            f"Limits(max_connections={self.max_connections!r}, "
            f"max_keepalive_connections={self.max_keepalive_connections!r}, "
            f"keepalive_expiry={self.keepalive_expiry!r})"
        )


class MockTransport:
    """Offline mock transport (`httpx.MockTransport`-compatible) for deterministic unit testing.

    `handler` receives a dict `{"method", "url", "headers", "params", "cookies", "data", "json"}`
    and returns either a `Response`, a `(status_code, body)` tuple, or a dict
    `{"status_code": 200, "json": {...}, "headers": {...}}`.
    """

    def __init__(self, handler: Callable[[Dict[str, Any]], Any]) -> None:
        self.handler = handler

    def _coerce(self, url: str, result: Any) -> "Response":
        if isinstance(result, Response):
            return result
        if isinstance(result, tuple) and len(result) >= 2:
            status = int(result[0])
            body = result[1]
            hdrs = dict(result[2]) if len(result) >= 3 and isinstance(result[2], dict) else {}
            raw = body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8")
            return Response(status_code=status, headers=hdrs, content=bytes(raw), url=url)
        if isinstance(result, dict):
            status = int(result.get("status_code", 200))
            hdrs = dict(result.get("headers") or {})
            if "json" in result:
                raw = _json.dumps(result["json"]).encode("utf-8")
                hdrs.setdefault("Content-Type", "application/json")
            elif "content" in result:
                c = result["content"]
                raw = c if isinstance(c, (bytes, bytearray)) else str(c).encode("utf-8")
            else:
                raw = str(result.get("text", "")).encode("utf-8")
            return Response(
                status_code=status,
                headers=hdrs,
                content=bytes(raw),
                url=str(result.get("url", url)),
                cookies=result.get("cookies"),
                http_version=str(result.get("http_version", "HTTP/2")),
            )
        raise TypeError("MockTransport handler must return Response, (status, body), or dict")

    def handle_request(self, request_ctx: Dict[str, Any]) -> "Response":
        res = self.handler(request_ctx)
        if inspect.isawaitable(res):
            raise RuntimeError("Async MockTransport handler must be used with AsyncSession / AsyncClient")
        return self._coerce(request_ctx["url"], res)

    async def handle_async_request(self, request_ctx: Dict[str, Any]) -> "Response":
        res = self.handler(request_ctx)
        if inspect.isawaitable(res):
            res = await res
        return self._coerce(request_ctx["url"], res)


def _unpack_timeout(
    timeout: Union[float, int, Tuple[Optional[float], Optional[float]], TimeoutConfig, None],
    connect_timeout: Optional[float] = None,
    read_timeout: Optional[float] = None,
) -> Tuple[float, Optional[float], Optional[float]]:
    if isinstance(timeout, TimeoutConfig):
        ct = connect_timeout if connect_timeout is not None else timeout.connect
        rt = read_timeout if read_timeout is not None else timeout.read
        return timeout.total(), ct, rt
    if isinstance(timeout, tuple) and len(timeout) == 2:
        t_conn, t_read = timeout
        ct = connect_timeout if connect_timeout is not None else (float(t_conn) if t_conn is not None else None)
        rt = read_timeout if read_timeout is not None else (float(t_read) if t_read is not None else None)
        vals = [v for v in (ct, rt) if v is not None]
        total = max(vals) if vals else 30.0
        return total, ct, rt
    total = float(timeout) if timeout is not None else 30.0
    return total, connect_timeout, read_timeout


_AKAMAI_SETTING_KEYS: Dict[int, str] = {
    1: "header_table_size",
    2: "enable_push",
    3: "max_concurrent_streams",
    4: "initial_window_size",
    5: "max_frame_size",
    6: "max_header_list_size",
    8: "enable_connect_protocol",
    9: "no_rfc7540_priorities",
}


def parse_akamai_h2_to_http2_options(akamai_fp: str) -> Dict[str, Any]:
    """Parse an Akamai HTTP/2 fingerprint string into `http2_options`.

    Format: `<SETTINGS>|<WINDOW_UPDATE>|<PRIORITIES>|<PSEUDO_ORDER>`
    Example: `"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"`
    """
    parts = akamai_fp.strip().split("|")
    if len(parts) != 4:
        raise ValueError(
            "Invalid Akamai HTTP/2 fingerprint: expected 4 pipe-separated fields "
            "(SETTINGS|WINDOW_UPDATE|PRIORITIES|PSEUDO_ORDER)"
        )
    settings_s, win_s, prio_s, pseudo_s = parts
    opts: Dict[str, Any] = {}

    if settings_s:
        order: List[int] = []
        for pair in settings_s.split(";"):
            pair = pair.strip()
            if not pair or ":" not in pair:
                continue
            sid_s, val_s = pair.split(":", 1)
            sid, val = int(sid_s.strip()), int(val_s.strip())
            key = _AKAMAI_SETTING_KEYS.get(sid)
            if key is None:
                continue
            order.append(sid)
            if key in ("enable_push", "enable_connect_protocol", "no_rfc7540_priorities"):
                opts[key] = bool(val)
            else:
                opts[key] = val
        if order:
            opts["settings_order"] = order

    if win_s and win_s.strip() not in ("0", "00"):
        win_update = int(win_s.strip())
        # Akamai's WINDOW_UPDATE field is (initial_connection_window_size - 65535)
        opts["initial_connection_window_size"] = win_update + 65535

    if prio_s and prio_s.strip() != "0":
        prios: List[Dict[str, Any]] = []
        for entry in prio_s.split(","):
            entry = entry.strip()
            if not entry:
                continue
            fields = entry.split(":")
            if len(fields) == 4:
                sid_i, excl_i, dep_i, weight_i = (int(x) for x in fields)
                prios.append(
                    {
                        "stream_id": sid_i,
                        "exclusive": bool(excl_i),
                        "dependency_id": dep_i,
                        "weight": max(0, min(255, weight_i - 1 if weight_i > 0 else 0)),
                    }
                )
        if prios:
            opts["priorities"] = prios

    if pseudo_s:
        pseudo = [p.strip() for p in pseudo_s.split(",") if p.strip()]
        if pseudo:
            opts["headers_pseudo_order"] = pseudo

    return opts


def _apply_fetch_headers(req_headers: Dict[str, str], fetch_mode: Optional[str], referer: Optional[str]) -> None:
    existing_lower = {k.lower() for k in req_headers}
    if referer and "referer" not in existing_lower:
        req_headers["Referer"] = referer
    if not fetch_mode:
        return
    mode = fetch_mode.strip().lower()
    if mode == "navigate":
        defaults = {
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin" if referer else "none",
            "Sec-Fetch-User": "?1",
        }
    elif mode in ("cors", "xhr", "fetch", "api"):
        defaults = {
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site" if referer else "cross-site",
        }
    elif mode == "same-origin":
        defaults = {
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }
    elif mode == "no-cors":
        defaults = {
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "cross-site",
        }
    else:
        raise ValueError(f"Unsupported fetch_mode '{fetch_mode}': expected navigate, cors, same-origin, or no-cors")
    for k, v in defaults.items():
        if k.lower() not in existing_lower:
            req_headers[k] = v


# ---------------------------------------------------------------------------
# JA3 string -> BoringSSL tls_options translator
# ---------------------------------------------------------------------------
_JA3_CIPHERS: Dict[int, str] = {
    4865: "TLS_AES_128_GCM_SHA256",
    4866: "TLS_AES_256_GCM_SHA384",
    4867: "TLS_CHACHA20_POLY1305_SHA256",
    49195: "ECDHE-ECDSA-AES128-GCM-SHA256",
    49196: "ECDHE-ECDSA-AES256-GCM-SHA384",
    49199: "ECDHE-RSA-AES128-GCM-SHA256",
    49200: "ECDHE-RSA-AES256-GCM-SHA384",
    52392: "ECDHE-RSA-CHACHA20-POLY1305",
    52393: "ECDHE-ECDSA-CHACHA20-POLY1305",
    49171: "ECDHE-RSA-AES128-SHA",
    49172: "ECDHE-RSA-AES256-SHA",
    49161: "ECDHE-ECDSA-AES128-SHA",
    49162: "ECDHE-ECDSA-AES256-SHA",
    156: "AES128-GCM-SHA256",
    157: "AES256-GCM-SHA384",
    47: "AES128-SHA",
    53: "AES256-SHA",
}

_JA3_CURVES: Dict[int, str] = {
    4588: "X25519MLKEM768",
    25497: "X25519Kyber768Draft00",
    29: "X25519",
    23: "P-256",
    24: "P-384",
    25: "P-521",
}

_JA3_TLS_VERSIONS: Dict[int, str] = {
    769: "1.0",
    770: "1.1",
    771: "1.2",
    772: "1.3",
}


def parse_ja3_to_tls_options(ja3: str) -> Dict[str, Any]:
    """Translate a standard 5-field JA3 string into BoringSSL `tls_options`."""
    parts = ja3.strip().split(",")
    if len(parts) != 5:
        raise ValueError("Invalid JA3 string: expected 5 comma-separated fields")
    ver_s, ciphers_s, _exts_s, curves_s, _pf_s = parts
    opts: Dict[str, Any] = {}
    if ver_s.isdigit() and int(ver_s) in _JA3_TLS_VERSIONS:
        opts["min_tls_version"] = _JA3_TLS_VERSIONS[int(ver_s)]
    if ciphers_s:
        mapped = [_JA3_CIPHERS[int(c)] for c in ciphers_s.split("-") if c.isdigit() and int(c) in _JA3_CIPHERS]
        if mapped:
            opts["cipher_list"] = ":".join(mapped)
    if curves_s:
        mapped_c = [_JA3_CURVES[int(c)] for c in curves_s.split("-") if c.isdigit() and int(c) in _JA3_CURVES]
        if mapped_c:
            opts["curves_list"] = ":".join(mapped_c)
    return opts


def _extract_proxy(proxy: Optional[str], proxies: Optional[Dict[str, str]]) -> Optional[str]:
    if proxy:
        return proxy
    if proxies:
        return proxies.get("all") or proxies.get("https") or proxies.get("http")
    return None


_ERROR_KINDS = {
    "connect_timeout": ConnectTimeout,
    "timeout": ReadTimeout,
    "redirect": TooManyRedirects,
    "ssl": SSLError,
    "connect": ConnectionError,
    "request": RequestException,
}


def _translate_error(exc: BaseException) -> RequestException:
    msg = str(exc)
    if msg.startswith("[") and "]" in msg:
        kind, _, rest = msg[1:].partition("]")
        cls = _ERROR_KINDS.get(kind)
        if cls is not None:
            return cls(rest.strip())
    mro = [k.__name__ for k in type(exc).__mro__]
    for cls in (ConnectTimeout, ReadTimeout, SSLError, TooManyRedirects, Timeout, ConnectionError):
        if cls.__name__ in mro:
            return cls(msg)
    if any("Certificate" in n or "SSL" in n for n in mro):
        return SSLError(msg)
    if any("Timeout" in n for n in mro):
        return Timeout(msg)
    return RequestException(msg)


def _read_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _split_verify(verify: Union[bool, str, None]) -> Tuple[bool, Optional[str]]:
    if isinstance(verify, str):
        return True, verify
    return (True if verify is None else verify), None


_PEM_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)
_PEM_KEY_RE = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL)


def _split_identity(cert: Union[str, Tuple[str, str], None]) -> Tuple[Optional[bytes], Optional[bytes]]:
    if cert is None:
        return None, None
    if isinstance(cert, (tuple, list)):
        crt, key = cert
        return _read_file(crt), _read_file(key)
    raw = _read_file(cert)
    certs = b"\n".join(_PEM_CERT_RE.findall(raw))
    keys = _PEM_KEY_RE.findall(raw)
    if not certs or not keys:
        raise ValueError("Combined PEM must contain both a CERTIFICATE block and a PRIVATE KEY block")
    return certs, keys[0]


def _normalize_files(files: Any) -> Optional[List[Tuple[str, Optional[str], bytes, Optional[str]]]]:
    if not files:
        return None
    pairs = files.items() if isinstance(files, dict) else list(files)
    out: List[Tuple[str, Optional[str], bytes, Optional[str]]] = []
    for field, spec in pairs:
        filename: Optional[str] = None
        content_type: Optional[str] = None
        if isinstance(spec, (tuple, list)):
            if len(spec) == 2:
                filename, obj = spec
            elif len(spec) >= 3:
                filename, obj, content_type = spec[0], spec[1], spec[2]
            else:
                raise ValueError("files tuple must have 2 or 3 elements: (filename, data[, content_type])")
        else:
            obj = spec
            if hasattr(obj, "name") and isinstance(obj.name, str):
                filename = os.path.basename(obj.name)
        raw = obj.read() if hasattr(obj, "read") else obj
        payload = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
        out.append((str(field), filename, payload, content_type))
    return out


def _coerce_auth(auth: Any) -> Optional[AuthBase]:
    if auth is None:
        return None
    if isinstance(auth, AuthBase):
        return auth
    if isinstance(auth, (tuple, list)) and len(auth) == 2:
        return BasicAuth(str(auth[0]), str(auth[1]))
    raise ValueError("auth must be (username, password), BasicAuth, BearerAuth, or DigestAuth")


class Cookies(dict):
    """RFC 6265 domain/path-aware cookie container with bidirectional Rust cookie jar sync."""

    def __init__(
        self,
        initial: Optional[Dict[str, str]] = None,
        on_clear: Optional[Callable[[], None]] = None,
        on_set: Optional[Callable[[str, str, Optional[str], Optional[str], bool, bool], None]] = None,
        on_delete: Optional[Callable[[str, Optional[str], Optional[str]], None]] = None,
    ) -> None:
        super().__init__(initial or {})
        self._on_clear = on_clear
        self._on_set = on_set
        self._on_delete = on_delete
        # Unscoped default cookies explicitly set by caller without a domain
        self._unscoped: Dict[str, str] = dict(initial or {})
        # Domain/path-scoped cookies: (domain, path, name) -> metadata dict
        self._scoped: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    @staticmethod
    def _norm_domain(domain: Optional[str]) -> str:
        return (domain or "").strip().lstrip(".").lower()

    @staticmethod
    def _domain_matches(req_host: str, cookie_dom: str) -> bool:
        if not cookie_dom or not req_host:
            return not cookie_dom
        h = req_host.strip().lstrip(".").lower()
        d = cookie_dom.strip().lstrip(".").lower()
        return h == d or h.endswith("." + d)

    @staticmethod
    def _path_matches(req_path: str, cookie_path: str) -> bool:
        cp = cookie_path or "/"
        rp = req_path or "/"
        if rp == cp:
            return True
        if rp.startswith(cp):
            return cp.endswith("/") or rp[len(cp):].startswith("/")
        return False

    def _refresh_view_key(self, name: str) -> None:
        if name in self._unscoped:
            super().__setitem__(name, self._unscoped[name])
            return
        for (_dom, _path, cname), rec in reversed(list(self._scoped.items())):
            if cname == name:
                super().__setitem__(name, rec["value"])
                return
        if super().__contains__(name):
            super().__delitem__(name)

    def __setitem__(self, name: str, value: str) -> None:
        self.set(name, value)

    def __delitem__(self, name: str) -> None:
        if not super().__contains__(name):
            raise KeyError(name)
        self.delete(name)

    def update(self, other: Any = None, **kwargs: Any) -> None:  # type: ignore[override]
        items: List[Tuple[Any, Any]] = []
        if other is not None:
            if hasattr(other, "items"):
                items.extend(other.items())
            else:
                items.extend(other)
        items.extend(kwargs.items())
        for k, v in items:
            self.set(str(k), str(v))

    def _sync_from_response(
        self,
        resp_cookies: Dict[str, str],
        jar_entries: Optional[Sequence[Tuple[str, str, str, str, bool, bool]]] = None,
    ) -> None:
        """Synchronize domain/path-scoped cookies from the Rust cookie jar without polluting unscoped defaults."""
        if jar_entries is not None:
            self._scoped.clear()
            for name, val, dom, cpath, sec, ho in jar_entries:
                d_norm = self._norm_domain(dom)
                p_norm = cpath or "/"
                self._scoped[(d_norm, p_norm, name)] = {
                    "name": name,
                    "value": val,
                    "domain": d_norm,
                    "path": p_norm,
                    "secure": sec,
                    "httpOnly": ho,
                }
                super().__setitem__(name, val)
        for k, v in resp_cookies.items():
            super().__setitem__(k, v)

    def clear(self) -> None:
        super().clear()
        self._unscoped.clear()
        self._scoped.clear()
        if self._on_clear is not None:
            self._on_clear()

    def set(
        self,
        name: str,
        value: str,
        domain: Optional[str] = None,
        path: Optional[str] = None,
        secure: bool = False,
        http_only: bool = False,
    ) -> None:
        d_norm = self._norm_domain(domain)
        p_norm = (path or "/").strip() or "/"
        if d_norm:
            self._scoped[(d_norm, p_norm, name)] = {
                "name": name,
                "value": value,
                "domain": d_norm,
                "path": p_norm,
                "secure": secure,
                "httpOnly": http_only,
            }
            if self._on_set is not None:
                self._on_set(name, value, d_norm, p_norm, secure, http_only)
            super().__setitem__(name, value)
        else:
            self._unscoped[name] = value
            super().__setitem__(name, value)

    def get(
        self,
        name: str,
        default: Any = None,
        domain: Optional[str] = None,
        path: Optional[str] = None,
    ) -> Any:
        if domain is not None or path is not None:
            d_norm = self._norm_domain(domain) if domain is not None else None
            for (cdom, cpath, cname), rec in reversed(list(self._scoped.items())):
                if cname != name:
                    continue
                if d_norm is not None and not self._domain_matches(d_norm, cdom):
                    continue
                if path is not None and not self._path_matches(path, cpath):
                    continue
                return rec["value"]
            if d_norm is None and name in self._unscoped:
                return self._unscoped[name]
            return default
        return super().get(name, default)

    def delete(self, name: str, domain: Optional[str] = None, path: Optional[str] = None) -> None:
        d_norm = self._norm_domain(domain) if domain is not None else None
        if d_norm is None and path is None:
            self._unscoped.pop(name, None)
        to_remove = [
            key
            for key in self._scoped
            if key[2] == name
            and (d_norm is None or key[0] == d_norm)
            and (path is None or key[1] == path)
        ]
        for key in to_remove:
            del self._scoped[key]
        if self._on_delete is not None:
            self._on_delete(name, d_norm, path)
        self._refresh_view_key(name)

    def get_dict(self, domain: Optional[str] = None, path: Optional[str] = None) -> Dict[str, str]:
        """Return cookies as a dictionary, optionally filtered by `domain` and `path` (requests-compatible)."""
        if domain is None and path is None:
            return dict(self)
        d_norm = self._norm_domain(domain) if domain is not None else None
        out: Dict[str, str] = {}
        if d_norm is None:
            out.update(self._unscoped)
        for (cdom, cpath, cname), rec in self._scoped.items():
            if d_norm is not None and not self._domain_matches(d_norm, cdom):
                continue
            if path is not None and not self._path_matches(path, cpath):
                continue
            out[cname] = rec["value"]
        return out

    def unscoped_for_url(self, url: str, extra: Optional[Dict[str, str]] = None) -> Optional[Dict[str, str]]:
        """Return only unscoped default cookies (not overshadowed by domain-scoped jar entries) + explicit request cookies."""
        if not self._unscoped and not extra:
            return None
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        req_path = parsed.path or "/"
        scoped_for_host = {
            cname
            for (cdom, cpath, cname) in self._scoped
            if cdom and self._domain_matches(host, cdom) and self._path_matches(req_path, cpath)
        }
        out: Dict[str, str] = {
            k: v for k, v in self._unscoped.items() if k not in scoped_for_host
        }
        if extra:
            out.update(extra)
        return out or None


class _OkDescriptor:
    def __init__(self, is_ok: bool):
        self._is_ok = is_ok

    def __bool__(self) -> bool:
        return self._is_ok

    def __call__(self) -> bool:
        return self._is_ok

    def __repr__(self) -> str:
        return str(self._is_ok)


class Response:
    """Unified Response object compatible with requests.Response and httpx.Response."""

    def __init__(
        self,
        status_code: int,
        headers: Dict[str, str],
        url: str,
        content: Optional[bytes] = b"",
        text: Optional[str] = None,
        encoding: Optional[str] = "utf-8",
        elapsed: float = 0.0,
        cookies: Optional[Dict[str, str]] = None,
        http_version: str = "HTTP/1.1",
        remote_addr: Optional[str] = None,
        peer_certificate: Optional[bytes] = None,
        history: Optional[List["Response"]] = None,
        proxy: Optional[str] = None,
        ech_accepted: bool = False,
        tls_resumed: bool = False,
        *,
        raw_chunks: Optional[Iterator[bytes]] = None,
        async_stream: Optional[Any] = None,
        closer: Optional[Callable[[], None]] = None,
    ) -> None:
        self.status_code = status_code
        self.headers = CaseInsensitiveDict(headers)
        self.url = url
        self.encoding = encoding or None
        self.elapsed = elapsed
        self.cookies = Cookies(cookies)
        self.http_version = http_version
        self.remote_addr = remote_addr
        self.peer_certificate = peer_certificate
        self.history: List["Response"] = history or []
        self.proxy: Optional[str] = proxy
        self.ech_accepted: bool = ech_accepted
        self.tls_resumed: bool = tls_resumed
        self._raw_chunks = raw_chunks
        self._async_stream = async_stream
        self._closer = closer
        self._content: Optional[bytes] = None if (raw_chunks is not None or async_stream is not None) else (content or b"")
        self._text = text
        self._num_bytes_downloaded: int = len(self._content) if self._content is not None else 0
        self._doc_cache: Optional[Any] = None
        self._json_cache: Optional[Any] = None

    @property
    def content(self) -> bytes:
        if self._content is None:
            self._content = b"".join(self._drain())
        return self._content

    @property
    def text(self) -> str:
        if self._text is None:
            self._text = self.content.decode(self.encoding or "utf-8", errors="replace")
        return self._text

    @property
    def apparent_encoding(self) -> str:
        return self.encoding or "utf-8"

    def _drain(self) -> Iterator[bytes]:
        if self._raw_chunks is None:
            if self._async_stream is not None:
                stream, self._async_stream = self._async_stream, None
                try:
                    while True:
                        chunk = stream.read_chunk()
                        if chunk is None:
                            return
                        if chunk:
                            self._num_bytes_downloaded += len(chunk)
                            yield chunk
                finally:
                    self.close()
                return
            raise RuntimeError("The content for this response was already consumed")
        chunks, self._raw_chunks = self._raw_chunks, None
        try:
            for chunk in chunks:
                if chunk:
                    self._num_bytes_downloaded += len(chunk)
                    yield chunk
        finally:
            self.close()

    def iter_content(self, chunk_size: Optional[int] = 1, decode_unicode: bool = False) -> Iterator[Any]:
        if self._content is not None:
            data = self._content
            step = chunk_size or len(data) or 1
            source: Iterator[bytes] = (data[i:i + step] for i in range(0, len(data), step))
        elif chunk_size is None:
            source = self._drain()
        else:
            source = self._rechunk(self._drain(), chunk_size)

        if not decode_unicode:
            yield from source
            return
        decoder = codecs.getincrementaldecoder(self.encoding or "utf-8")(errors="replace")
        for chunk in source:
            out = decoder.decode(chunk)
            if out:
                yield out
        tail = decoder.decode(b"", final=True)
        if tail:
            yield tail

    async def aiter_bytes(self, chunk_size: Optional[int] = None) -> AsyncIterator[bytes]:
        if self._content is not None:
            data = self._content
            step = chunk_size or len(data) or 1
            for i in range(0, len(data), step):
                yield data[i:i + step]
            return
        if self._async_stream is None:
            for chunk in self.iter_content(chunk_size=chunk_size):
                yield chunk
            return
        stream, self._async_stream = self._async_stream, None
        buf = bytearray()
        try:
            while True:
                raw = await stream.aread_chunk()
                if raw is None:
                    break
                chunk = bytes(raw)
                if not chunk:
                    continue
                self._num_bytes_downloaded += len(chunk)
                if chunk_size is None:
                    yield chunk
                else:
                    buf += chunk
                    while len(buf) >= chunk_size:
                        yield bytes(buf[:chunk_size])
                        del buf[:chunk_size]
            if buf:
                yield bytes(buf)
        finally:
            await self.aclose()

    async def aiter_lines(self) -> AsyncIterator[str]:
        decoder = codecs.getincrementaldecoder(self.encoding or "utf-8")(errors="replace")
        pending = ""
        async for chunk in self.aiter_bytes():
            text = pending + decoder.decode(chunk)
            lines = text.splitlines()
            if lines and text and not text.endswith(("\n", "\r")):
                pending = lines.pop()
            else:
                pending = ""
            for line in lines:
                yield line
        tail = pending + decoder.decode(b"", final=True)
        if tail:
            for line in tail.splitlines():
                yield line

    @staticmethod
    def _rechunk(source: Iterator[bytes], size: int) -> Iterator[bytes]:
        buf = bytearray()
        for chunk in source:
            buf += chunk
            while len(buf) >= size:
                yield bytes(buf[:size])
                del buf[:size]
        if buf:
            yield bytes(buf)

    def iter_lines(
        self, chunk_size: int = 512, decode_unicode: bool = False, delimiter: Optional[Any] = None
    ) -> Iterator[Any]:
        pending = None
        for chunk in self.iter_content(chunk_size=chunk_size, decode_unicode=decode_unicode):
            if pending is not None:
                chunk = pending + chunk
            lines = chunk.split(delimiter) if delimiter else chunk.splitlines()
            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            else:
                pending = None
            yield from lines
        if pending is not None:
            yield pending

    def close(self) -> None:
        closer, self._closer = self._closer, None
        if closer is not None:
            try:
                closer()
            except Exception:
                pass

    async def aclose(self) -> None:
        if self._async_stream is not None:
            s, self._async_stream = self._async_stream, None
            try:
                await s.aclose()
            except Exception:
                pass
        self.close()

    @property
    def ok(self) -> _OkDescriptor:
        return _OkDescriptor(200 <= self.status_code < 400)

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_informational(self) -> bool:
        return 100 <= self.status_code < 200

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_permanent_redirect(self) -> bool:
        return self.status_code in (301, 308) and "location" in self.headers

    @property
    def has_redirect_location(self) -> bool:
        return self.is_redirect and "location" in self.headers

    @property
    def num_bytes_downloaded(self) -> int:
        return self._num_bytes_downloaded

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600

    @property
    def is_error(self) -> bool:
        return 400 <= self.status_code < 600

    def read(self) -> bytes:
        return self.content

    async def aread(self) -> bytes:
        if self._content is None:
            chunks = [c async for c in self.aiter_bytes()]
            self._content = b"".join(chunks)
        return self._content

    async def acontent(self) -> bytes:
        """Asynchronously read response bytes (curl_cffi compatible)."""
        return await self.aread()

    async def atext(self) -> str:
        """Asynchronously read and decode response text (curl_cffi compatible)."""
        raw = await self.aread()
        if self._text is None:
            self._text = raw.decode(self.encoding or "utf-8", errors="replace")
        return self._text

    def iter_bytes(self, chunk_size: Optional[int] = None) -> Iterator[bytes]:
        """Iterate over response bytes (httpx compatible)."""
        return self.iter_content(chunk_size=chunk_size, decode_unicode=False)

    def iter_text(self, chunk_size: Optional[int] = None) -> Iterator[str]:
        """Iterate over decoded response text chunks (httpx compatible)."""
        return self.iter_content(chunk_size=chunk_size, decode_unicode=True)

    async def aiter_content(self, chunk_size: Optional[int] = None) -> AsyncIterator[bytes]:
        """Asynchronously iterate over response bytes (curl_cffi compatible)."""
        async for chunk in self.aiter_bytes(chunk_size=chunk_size):
            yield chunk

    async def aiter_text(self, chunk_size: Optional[int] = None) -> AsyncIterator[str]:
        """Asynchronously iterate over decoded text chunks (httpx compatible)."""
        decoder = codecs.getincrementaldecoder(self.encoding or "utf-8")(errors="replace")
        async for chunk in self.aiter_bytes(chunk_size=chunk_size):
            out = decoder.decode(chunk)
            if out:
                yield out
        tail = decoder.decode(b"", final=True)
        if tail:
            yield tail

    @property
    def reason(self) -> str:
        try:
            from http import HTTPStatus
            return HTTPStatus(self.status_code).phrase
        except ValueError:
            return ""

    @property
    def reason_phrase(self) -> str:
        """HTTP reason phrase (httpx compatible alias for `reason`)."""
        return self.reason

    @property
    def links(self) -> Dict[str, Dict[str, str]]:
        """Parse RFC 8288 `Link` header into `{rel: {"url": ..., "rel": ...}}` (requests/httpx compatible)."""
        header = self.headers.get("link", "")
        if not header:
            return {}
        out: Dict[str, Dict[str, str]] = {}
        for part in header.split(","):
            seg = part.strip()
            if not seg or not seg.startswith("<") or ">" not in seg:
                continue
            url_val, _, rest = seg[1:].partition(">")
            entry: Dict[str, str] = {"url": url_val.strip()}
            for param in rest.split(";"):
                if "=" in param:
                    k, _, v = param.partition("=")
                    entry[k.strip().lower()] = v.strip().strip('"').strip("'")
            key = entry.get("rel") or entry["url"]
            out[key] = entry
        return out

    @property
    def challenge(self) -> Optional[str]:
        return _challenge.detect(self)

    @property
    def alt_svc(self) -> Dict[str, str]:
        """Parse RFC 7838 `Alt-Svc` header (e.g. `h3=":443"; ma=86400`) into `{protocol: authority}`."""
        raw = self.headers.get("alt-svc", "").strip()
        if not raw or raw.lower() == "clear":
            return {}
        out: Dict[str, str] = {}
        for item in raw.split(","):
            seg = item.strip()
            if not seg:
                continue
            proto_part = seg.split(";", 1)[0].strip()
            if "=" in proto_part:
                proto, _, auth = proto_part.partition("=")
                p_clean = proto.strip().lower()
                a_clean = auth.strip().strip('"')
                if p_clean and a_clean:
                    out[p_clean] = a_clean
        return out

    def json(self, **kwargs: Any) -> Any:
        return _json.loads(self.text, **kwargs)

    _XPATH_AXES: Tuple[str, ...] = (
        "child::",
        "descendant::",
        "descendant-or-self::",
        "parent::",
        "ancestor::",
        "ancestor-or-self::",
        "following-sibling::",
        "preceding-sibling::",
        "following::",
        "preceding::",
        "self::",
        "attribute::",
    )

    @classmethod
    def _is_xpath_query(cls, q: str) -> bool:
        return q.startswith(("/", "./", "../", "(", "@")) or any(axis in q for axis in cls._XPATH_AXES)

    def _get_doc(self) -> Any:
        if _rust_parse_html is None:
            raise RuntimeError("Rust native HTML5 engine '_core' not compiled.")
        if self._doc_cache is None:
            self._doc_cache = _rust_parse_html(self.text)
        return self._doc_cache

    @property
    def html_doc(self) -> Any:
        """Lazily parsed Rust WHATWG HTML5 `HtmlDocument` cached on this response (thread-safe)."""
        return self._get_doc()

    def css(self, selector: str) -> List[Any]:
        """Query HTML with Rust CSS3 selectors (`:has()`, `:contains()`, `:has-text()`, `::text`, `::attr(name)`)."""
        return self._get_doc().css(selector)

    def css_first(self, selector: str, default: Any = None) -> Optional[Any]:
        """Return the first Rust CSS3 selector match (or `default`)."""
        return self._get_doc().css_first(selector, default)

    def select(self, selector: str) -> List[Any]:
        """BeautifulSoup-compatible alias for `css(selector)`."""
        return self._get_doc().css(selector)

    def select_one(self, selector: str, default: Any = None) -> Optional[Any]:
        """BeautifulSoup-compatible alias for `css_first(selector, default=default)`."""
        return self._get_doc().css_first(selector, default)

    def xpath(self, expr: str) -> List[Any]:
        """Query HTML with the native Rust XPath 1.0 evaluator (axes, predicates, `text()`, `@attr`, `|`)."""
        return self._get_doc().xpath(expr)

    def xpath_first(self, expr: str, default: Any = None) -> Optional[Any]:
        """Return the first native Rust XPath match (or `default`)."""
        return self._get_doc().xpath_first(expr, default)

    def find(self, query: str, default: Any = None) -> Optional[Any]:
        """Auto-dispatch first match: JSON path (`$.`, `$..`, `$[`), XPath (`/...`, `.//...`, XPath axes), or CSS3 (incl. `::text`/`::attr(...)`)."""
        q = query.strip()
        if q.startswith(("$.", "$[")):
            return self.json_path(q, default=default)
        if self._is_xpath_query(q):
            return self.xpath_first(q, default)
        return self.css_first(q, default)

    def find_all(self, query: str) -> List[Any]:
        """Auto-dispatch all matches: JSON path (`$.`, `$..`, `$[`), XPath (`/...`, `.//...`, XPath axes), or CSS3 (incl. `::text`/`::attr(...)`)."""
        q = query.strip()
        if q.startswith(("$.", "$[")):
            val = self.json_path(q, default=None)
            if val is None:
                return []
            return val if isinstance(val, list) else [val]
        if self._is_xpath_query(q):
            return self.xpath(q)
        return self.css(q)

    def get_text(self, separator: str = " ", strip: bool = True) -> str:
        """BeautifulSoup-compatible text extraction joining all HTML text nodes with `separator`."""
        return self._get_doc().get_text(separator, strip)

    def urljoin(self, url: str) -> str:
        """Scrapy-compatible absolute URL resolver relative to `self.url`."""
        return urljoin(self.url, url)

    def re(self, pattern: str) -> List[str]:
        """Extract all regex matches from `self.text` using Rust's linear-time DFA regex engine (ReDoS-safe)."""
        if _rust_extract_re is None:
            raise RuntimeError("Rust native regex engine '_core' not compiled.")
        return _rust_extract_re(self.text, pattern)

    def re_first(self, pattern: str, default: Optional[str] = None) -> Optional[str]:
        """Return the first regex match from `self.text` (or `default`) using Rust's linear-time DFA regex engine."""
        if _rust_extract_re_first is None:
            raise RuntimeError("Rust native regex engine '_core' not compiled.")
        res = _rust_extract_re_first(self.text, pattern)
        return default if res is None else res

    def between(self, left: str, right: str, default: Optional[str] = None) -> Optional[str]:
        """Extract the first substring between `left` and `right` delimiters from `self.text` in Rust (or `default`)."""
        if _rust_extract_between is None:
            raise RuntimeError("Rust native extraction engine '_core' not compiled.")
        res = _rust_extract_between(self.text, left, right)
        return default if res is None else res

    def between_all(self, left: str, right: str) -> List[str]:
        """Extract all substrings between `left` and `right` delimiters from `self.text` in Rust."""
        if _rust_extract_between_all is None:
            raise RuntimeError("Rust native extraction engine '_core' not compiled.")
        return _rust_extract_between_all(self.text, left, right)

    def _get_json_doc(self) -> Any:
        if _rust_parse_json is None:
            raise RuntimeError("Rust native JSON engine '_core' not compiled.")
        if self._json_cache is None:
            self._json_cache = _rust_parse_json(self.text)
        return self._json_cache

    @property
    def json_doc(self) -> Any:
        """Lazily parsed Rust `JsonDocument` (`serde_json::Value`) cached on this response."""
        return self._get_json_doc()

    def json_path(self, path: str, default: Any = None) -> Any:
        """Extract a nested value from JSON in Rust (`a.b[0].c`, `items[-1].id`, `items[0:5]`, `items[*].name`, `items[?(@.price>10)].name`, `$..price`)."""
        if _rust_parse_json is not None:
            found, val = self._get_json_doc().query(path)
            return val if found else default
        if _rust_extract_json_path is None:
            raise RuntimeError("Rust native JSON engine '_core' not compiled.")
        found, val = _rust_extract_json_path(self.text, path)
        return val if found else default

    def raise_for_status(self) -> None:
        if 400 <= self.status_code < 500:
            raise HTTPError(f"{self.status_code} Client Error: {self.reason} for url: {self.url}", response=self)
        if 500 <= self.status_code < 600:
            raise HTTPError(f"{self.status_code} Server Error: {self.reason} for url: {self.url}", response=self)

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    async def __aenter__(self) -> "Response":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}]>"

    def __bytes__(self) -> bytes:
        return self.content


class WebSocket:
    """Synchronous TLS-impersonated WebSocket connection backed by Rust BoringSSL."""

    def __init__(self, native: Any) -> None:
        self._ws = native
        self.status_code: int = native.status_code
        self.headers = CaseInsensitiveDict(native.headers)
        self.protocol: Optional[str] = native.protocol

    def send_text(self, text: str) -> None:
        try:
            self._ws.send_text(text)
        except RuntimeError as exc:
            raise _translate_error(exc) from exc

    def send_bytes(self, data: bytes) -> None:
        try:
            self._ws.send_bytes(data)
        except RuntimeError as exc:
            raise _translate_error(exc) from exc

    def send_json(self, obj: Any) -> None:
        self.send_text(_json.dumps(obj))

    def recv(self) -> Optional[Tuple[str, bytes]]:
        try:
            return self._ws.recv()
        except RuntimeError as exc:
            raise _translate_error(exc) from exc

    def recv_text(self) -> Optional[str]:
        msg = self.recv()
        return None if msg is None else msg[1].decode("utf-8", errors="replace")

    def recv_json(self) -> Any:
        txt = self.recv_text()
        return None if txt is None else _json.loads(txt)

    def close(self, code: int = 1000, reason: str = "") -> None:
        self._ws.close(code, reason)

    def __enter__(self) -> "WebSocket":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class AsyncWebSocket:
    """Native Tokio asynchronous TLS-impersonated WebSocket connection."""

    def __init__(self, native: Any) -> None:
        self._ws = native
        self.status_code: int = native.status_code
        self.headers = CaseInsensitiveDict(native.headers)
        self.protocol: Optional[str] = native.protocol

    async def send_text(self, text: str) -> None:
        try:
            await self._ws.asend_text(text)
        except RuntimeError as exc:
            raise _translate_error(exc) from exc

    async def send_bytes(self, data: bytes) -> None:
        try:
            await self._ws.asend_bytes(data)
        except RuntimeError as exc:
            raise _translate_error(exc) from exc

    async def send_json(self, obj: Any) -> None:
        await self.send_text(_json.dumps(obj))

    async def recv(self) -> Optional[Tuple[str, bytes]]:
        try:
            res = await self._ws.arecv()
        except RuntimeError as exc:
            raise _translate_error(exc) from exc
        return None if res is None else (res[0], bytes(res[1]))

    async def recv_text(self) -> Optional[str]:
        msg = await self.recv()
        return None if msg is None else msg[1].decode("utf-8", errors="replace")

    async def recv_json(self) -> Any:
        txt = await self.recv_text()
        return None if txt is None else _json.loads(txt)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        await self._ws.aclose(code, reason)

    async def __aenter__(self) -> "AsyncWebSocket":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()


def _native_chunks(stream: Any) -> Iterator[bytes]:
    while True:
        chunk = stream.read_chunk()
        if chunk is None:
            return
        yield chunk


def _build_history_responses(raw_history: Sequence[Tuple[int, str, str, Dict[str, str]]]) -> List[Response]:
    return [
        Response(status_code=status, headers=hdrs, url=prev_url, content=b"", text="")
        for status, prev_url, _next_url, hdrs in raw_history
    ]


_INLINE_COOKIE_RE = re.compile(
    r"""document\.cookie\s*=\s*["']([A-Za-z0-9_\-\.]+)=([^;"']+)""",
    re.IGNORECASE,
)


def _try_extract_inline_cookie(text: str) -> Dict[str, str]:
    """Extract simple inline JS `document.cookie = 'k=v; ...'` tokens (e.g. CDN77 / lightweight interstitials)."""
    if not text:
        return {}
    return {m.group(1): m.group(2) for m in _INLINE_COOKIE_RE.finditer(text[:16384])}
