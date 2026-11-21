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
        Session as _RustSession,
        WebSocket as _NativeWebSocket,
        __version__,
        is_verified_preset as _rust_is_verified_preset,
        supported_presets as _rust_presets,
    )
except ImportError:
    _RustSession = None
    _NativeWebSocket = None
    __version__ = "0.7.1"

    def _rust_presets() -> List[str]:
        return []

    def _rust_is_verified_preset(preset: str) -> bool:
        return False


# Optional legacy curl_cffi backend (only used when explicitly requested via engine="curl_cffi")
_CffiSession: Any = None
try:
    from curl_cffi.requests.session import Session as _ImportedCffiSession
    _CffiSession = _ImportedCffiSession
    _HAS_CFFI = True
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
    return bool(True if verify is None else verify), None


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
        self.set(str(name), str(value))

    def __delitem__(self, name: str) -> None:
        if not super().__contains__(name):
            raise KeyError(name)
        self.delete(str(name))

    def update(self, other: Any = None, **kwargs: Any) -> None:  # type: ignore[override]
        items: List[Tuple[str, Any]] = []
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
                    "secure": bool(sec),
                    "httpOnly": bool(ho),
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
                "secure": bool(secure),
                "httpOnly": bool(http_only),
            }
            if self._on_set is not None:
                self._on_set(name, value, d_norm, p_norm, bool(secure), bool(http_only))
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
            out.update({str(k): str(v) for k, v in extra.items()})
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
        self._raw_chunks = raw_chunks
        self._async_stream = async_stream
        self._closer = closer
        self._content: Optional[bytes] = None if (raw_chunks is not None or async_stream is not None) else (content or b"")
        self._text = text
        self._num_bytes_downloaded: int = len(self._content) if self._content is not None else 0

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

    def json(self, **kwargs: Any) -> Any:
        return _json.loads(self.text, **kwargs)

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


class Session:
    """HTTP Session: 100% drop-in for requests.Session, httpx.Client, and curl_cffi.requests.Session."""

    def __init__(
        self,
        impersonate: Union[str, BrowserType] = "chrome_149",
        timeout: Union[float, int, Tuple[Optional[float], Optional[float]], TimeoutConfig] = 30.0,
        connect_timeout: Optional[float] = None,
        read_timeout: Optional[float] = None,
        verify: Union[bool, str] = True,
        verify_ssl: bool = True,
        proxies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        proxies_pool: Optional[Sequence[str]] = None,
        allow_redirects: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        headers: Optional[Dict[str, str]] = None,
        header_order: Optional[Sequence[str]] = None,
        params: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Union[Tuple[str, str], AuthBase]] = None,
        cert: Union[str, Tuple[str, str], None] = None,
        base_url: str = "",
        tls_options: Optional[Dict[str, Any]] = None,
        ja3: Optional[str] = None,
        http2_options: Optional[Dict[str, Any]] = None,
        akamai_h2: Optional[str] = None,
        http1_only: bool = False,
        http2_only: bool = False,
        resolve: Optional[Dict[str, Union[str, Sequence[str]]]] = None,
        local_address: Optional[str] = None,
        interface: Optional[str] = None,
        tls_info: bool = False,
        keylog_file: Optional[str] = None,
        system_dns: bool = False,
        record_har: bool = False,
        flare_solverr_url: Optional[str] = None,
        solver: Optional[Callable[[str, Response], Any]] = None,
        storage_state: Optional[Union[str, Dict[str, Any]]] = None,
        pool_max_idle_per_host: Optional[int] = None,
        pool_idle_timeout: Optional[float] = None,
        limits: Optional[Limits] = None,
        tcp_nodelay: Optional[bool] = None,
        tcp_keepalive: Optional[float] = None,
        auto_referer: bool = False,
        fetch_mode: Optional[str] = None,
        transport: Optional[MockTransport] = None,
        retries: int = 0,
        retry_backoff: float = 0.5,
        retry_statuses: Sequence[int] = (429, 500, 502, 503, 504),
        retry_on_challenge: bool = False,
        rotate_impersonate: bool = False,
        event_hooks: Optional[Dict[str, List[Callable[..., Any]]]] = None,
        engine: str = "auto",
        **kwargs: Any,
    ) -> None:
        if engine not in ("auto", "rust", "boring", "impersonate", "curl_cffi"):
            raise ValueError("engine must be 'auto', 'rust', 'boring', 'impersonate', or 'curl_cffi'")

        total_timeout, eff_connect_timeout, eff_read_timeout = _unpack_timeout(
            timeout, connect_timeout, read_timeout
        )
        if limits is not None:
            if pool_max_idle_per_host is None:
                pool_max_idle_per_host = limits.max_keepalive_connections or limits.max_connections
            if pool_idle_timeout is None and limits.keepalive_expiry is not None:
                pool_idle_timeout = limits.keepalive_expiry

        verify_flag, ca_path = _split_verify(verify)
        self.impersonate = str(impersonate)
        self.timeout = total_timeout
        self.verify: Union[bool, str] = ca_path if ca_path else (verify_flag and verify_ssl)
        self.cert = cert
        self.base_url = base_url
        self.max_redirects = max_redirects
        self.allow_redirects = allow_redirects and follow_redirects
        self.engine = engine
        self.auth = auth
        self.retries = max(0, int(retries))
        self.retry_backoff = float(retry_backoff)
        self.retry_statuses = tuple(retry_statuses)
        self.retry_on_challenge = bool(retry_on_challenge)
        self.rotate_impersonate = bool(rotate_impersonate)
        self.keylog_file = keylog_file
        self.system_dns = bool(system_dns)
        self.record_har = bool(record_har)
        self.har_entries: List[Dict[str, Any]] = []
        self.flare_solverr_url = flare_solverr_url
        self.solver = solver
        self.auto_referer = bool(auto_referer)
        self.fetch_mode = fetch_mode
        self.transport = transport
        self._last_url: Optional[str] = None
        self.proxies_pool: List[str] = list(proxies_pool) if proxies_pool else []
        self._proxy_idx = 0
        self.event_hooks: Dict[str, List[Callable[..., Any]]] = {
            "request": list((event_hooks or {}).get("request", [])),
            "response": list((event_hooks or {}).get("response", [])),
        }

        self.headers = CaseInsensitiveDict(headers or {})
        self.params: Dict[str, Any] = dict(params or {})
        self.cookies = Cookies(
            cookies,
            on_clear=self._clear_backend_cookies,
            on_set=self._set_backend_cookie,
            on_delete=self._delete_backend_cookie,
        )
        self._closed = False
        p_val = _extract_proxy(proxy, proxies)
        self.proxies = dict(proxies) if proxies else ({"all": proxy, "http": proxy, "https": proxy} if proxy else {})

        merged_tls: Optional[Dict[str, Any]] = None
        if ja3 or tls_options:
            merged_tls = {}
            if ja3:
                merged_tls.update(parse_ja3_to_tls_options(ja3))
            if tls_options:
                merged_tls.update(tls_options)

        merged_h2: Optional[Dict[str, Any]] = None
        if akamai_h2 or http2_options:
            merged_h2 = {}
            if akamai_h2:
                merged_h2.update(parse_akamai_h2_to_http2_options(akamai_h2))
            if http2_options:
                merged_h2.update(http2_options)

        if engine == "curl_cffi":
            if not _HAS_CFFI:
                raise RuntimeError('engine="curl_cffi" requires curl_cffi: pip install "http-tls[curl_cffi]"')
            self._mode = "curl_cffi"
            self._session = _CffiSession(
                impersonate=self.impersonate.replace("_", ""),
                timeout=total_timeout,
                max_redirects=max_redirects,
                verify=self.verify,
                proxies={"all": p_val, "http": p_val, "https": p_val} if p_val else None,
            )
        else:
            if _RustSession is None:
                raise RuntimeError("Rust native BoringSSL engine '_core' not compiled.")
            self._mode = "rust"
            client_cert, client_key = _split_identity(cert)
            self._session = _RustSession(
                impersonate=self.impersonate,
                timeout=total_timeout,
                follow_redirects=self.allow_redirects,
                max_redirects=max_redirects,
                verify_ssl=bool(self.verify),
                proxy=p_val,
                ca_bundle=_read_file(ca_path) if ca_path else None,
                client_cert=client_cert,
                client_key=client_key,
                header_order=list(header_order) if header_order else None,
                tls_options=merged_tls,
                http2_options=merged_h2,
                http1_only=http1_only,
                http2_only=http2_only,
                resolve=dict(resolve) if resolve else None,
                local_address=local_address,
                interface=interface,
                tls_info=tls_info,
                connect_timeout=eff_connect_timeout,
                read_timeout=eff_read_timeout,
                pool_max_idle_per_host=pool_max_idle_per_host,
                pool_idle_timeout=pool_idle_timeout,
                keylog_file=keylog_file,
                system_dns=self.system_dns,
                tcp_nodelay=tcp_nodelay,
                tcp_keepalive=tcp_keepalive,
            )
        if storage_state is not None:
            self.load_storage_state(storage_state)

    @property
    def mode(self) -> str:
        return self._mode

    def _next_pool_proxy(self) -> Optional[str]:
        if not self.proxies_pool:
            return None
        p = self.proxies_pool[self._proxy_idx % len(self.proxies_pool)]
        self._proxy_idx += 1
        return p

    def _resolve_url(self, url: str) -> str:
        if not self.base_url or url.startswith(("http://", "https://", "ws://", "wss://")):
            return url
        base = self.base_url if self.base_url.endswith("/") else self.base_url + "/"
        return urljoin(base, url.lstrip("/"))

    def _clear_backend_cookies(self) -> None:
        if self._mode == "rust":
            self._session.clear_cookies()
        elif hasattr(self._session, "cookies") and hasattr(self._session.cookies, "clear"):
            self._session.cookies.clear()

    def _set_backend_cookie(
        self,
        name: str,
        value: str,
        domain: Optional[str],
        path: Optional[str],
        secure: bool,
        http_only: bool,
    ) -> None:
        if self._mode == "rust" and hasattr(self._session, "set_cookie"):
            self._session.set_cookie(name, value, domain, path, secure, http_only)

    def _delete_backend_cookie(
        self,
        name: str,
        domain: Optional[str],
        path: Optional[str],
    ) -> None:
        if self._mode == "rust" and hasattr(self._session, "delete_cookie"):
            self._session.delete_cookie(name, domain, path)

    def clear_cookies(self) -> None:
        self.cookies.clear()

    def set_impersonate(self, preset: Union[str, BrowserType]) -> None:
        """Hot-swap the active browser impersonation profile (TLS JA3/JA4, HTTP/2, and default Client Hints)."""
        self.impersonate = str(preset)
        if self._mode == "rust" and hasattr(self._session, "set_impersonate"):
            self._session.set_impersonate(self.impersonate)

    def load_storage_state(
        self,
        state: Union[str, Dict[str, Any]],
        sync_impersonate: bool = True,
    ) -> Dict[str, Any]:
        """Load Playwright / Camoufox / solver `storage_state.json` into this Session.

        When `sync_impersonate=True` (the default), automatically aligns `self.impersonate`
        in the Rust BoringSSL engine with the browser version & OS in `User-Agent` so
        TLS JA4, HTTP/2 SETTINGS, `Sec-CH-UA*`, and `User-Agent` never mismatch.
        """
        data = _json.loads(_read_file(state).decode("utf-8")) if isinstance(state, str) else dict(state)
        explicit_imp = data.get("impersonate")
        ua = data.get("user_agent") or data.get("userAgent")
        if ua:
            ua_str = str(ua)
            self.headers["User-Agent"] = ua_str
            if sync_impersonate:
                target_imp = str(explicit_imp) if explicit_imp else infer_impersonate_from_user_agent(ua_str)
                if target_imp:
                    self.set_impersonate(target_imp)
        elif explicit_imp and sync_impersonate:
            self.set_impersonate(str(explicit_imp))

        if isinstance(data.get("headers"), dict):
            self.headers.update(data["headers"])

        raw_cookies = data.get("cookies", [])
        if isinstance(raw_cookies, dict):
            for k, v in raw_cookies.items():
                self.cookies.set(str(k), str(v))
        elif isinstance(raw_cookies, list):
            for c in raw_cookies:
                if not isinstance(c, dict) or "name" not in c or "value" not in c:
                    continue
                name, val = str(c["name"]), str(c["value"])
                dom = str(c.get("domain") or "").lstrip(".")
                path = str(c.get("path") or "/")
                sec = bool(c.get("secure", False))
                ho = bool(c.get("httpOnly", False))
                if dom:
                    self.cookies.set(name, val, domain=dom, path=path, secure=sec, http_only=ho)
                else:
                    self.cookies.set(name, val)
        return data

    def save_storage_state(self, path: Optional[str] = None) -> Dict[str, Any]:
        """Export current session cookies, User-Agent, and impersonate profile in Playwright `storage_state.json` format."""
        seen: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        if self._mode == "rust" and hasattr(self._session, "all_cookies"):
            for name, val, dom, cpath, sec, ho in self._session.all_cookies():
                d_clean = dom.lstrip(".")
                p_clean = cpath or "/"
                seen[(d_clean, p_clean, name)] = {
                    "name": name,
                    "value": val,
                    "domain": d_clean,
                    "path": p_clean,
                    "expires": -1,
                    "httpOnly": bool(ho),
                    "secure": bool(sec),
                    "sameSite": "Lax",
                }
        for (dom, cpath, name), rec in self.cookies._scoped.items():
            if (dom, cpath, name) not in seen:
                seen[(dom, cpath, name)] = {
                    "name": name,
                    "value": rec["value"],
                    "domain": dom,
                    "path": cpath,
                    "expires": -1,
                    "httpOnly": bool(rec.get("httpOnly", False)),
                    "secure": bool(rec.get("secure", False)),
                    "sameSite": "Lax",
                }
        existing_names = {k[2] for k in seen}
        for name, val in self.cookies._unscoped.items():
            if name not in existing_names:
                seen[("", "/", name)] = {
                    "name": name,
                    "value": val,
                    "domain": "",
                    "path": "/",
                    "expires": -1,
                    "httpOnly": False,
                    "secure": False,
                    "sameSite": "Lax",
                }
        state: Dict[str, Any] = {
            "cookies": list(seen.values()),
            "origins": [],
            "impersonate": self.impersonate,
        }
        ua = self.headers.get("user-agent")
        if ua:
            state["user_agent"] = ua
        if path is not None:
            with open(path, "w", encoding="utf-8") as fh:
                _json.dump(state, fh, indent=2)
        return state

    def _record_har_entry(self, method: str, url: str, req_headers: Optional[Dict[str, str]], resp: Response) -> None:
        if not self.record_har:
            return
        now_iso = _dt.datetime.now(_dt.timezone.utc).isoformat()
        server_ip = (resp.remote_addr or "").rsplit(":", 1)[0]
        self.har_entries.append(
            {
                "startedDateTime": now_iso,
                "time": round(resp.elapsed * 1000.0, 3),
                "serverIPAddress": server_ip,
                "request": {
                    "method": method.upper(),
                    "url": url,
                    "httpVersion": resp.http_version,
                    "headers": [{"name": k, "value": v} for k, v in (req_headers or {}).items()],
                    "cookies": [{"name": k, "value": v} for k, v in self.cookies.items()],
                    "queryString": [],
                    "headersSize": -1,
                    "bodySize": 0,
                },
                "response": {
                    "status": resp.status_code,
                    "statusText": resp.reason,
                    "httpVersion": resp.http_version,
                    "headers": [{"name": k, "value": v} for k, v in resp.headers.items()],
                    "cookies": [{"name": k, "value": v} for k, v in resp.cookies.items()],
                    "content": {
                        "size": len(resp._content or b""),
                        "mimeType": resp.headers.get("content-type", "application/octet-stream"),
                        "text": resp.text if resp._content is not None else "",
                    },
                    "redirectURL": resp.headers.get("location", ""),
                    "headersSize": -1,
                    "bodySize": len(resp._content or b""),
                },
                "cache": {},
                "timings": {"send": 0, "wait": round(resp.elapsed * 1000.0, 3), "receive": 0},
            }
        )

    def export_har(self, path: Optional[str] = None) -> Dict[str, Any]:
        """Export recorded requests/responses as a standard HAR 1.2 dictionary (and write to `path` if given)."""
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "http_tls", "version": __version__},
                "entries": list(self.har_entries),
            }
        }
        if path is not None:
            with open(path, "w", encoding="utf-8") as fh:
                _json.dump(har, fh, indent=2)
        return har

    def clear_har(self) -> None:
        """Clear recorded HAR entries."""
        self.har_entries.clear()

    def solve_challenge(self, url_or_resp: Union[str, Response]) -> bool:
        """Attempt to solve an anti-bot challenge via inline JS extraction, custom `solver`, or `flare_solverr_url`."""
        if isinstance(url_or_resp, Response):
            resp = url_or_resp
            target_url = resp.url
        else:
            target_url = self._resolve_url(url_or_resp)
            resp = self.get(target_url)

        inline = _try_extract_inline_cookie(resp.text)
        if inline:
            self.cookies.update(inline)
            if self._mode == "rust":
                for k, v in inline.items():
                    self._session.add_raw_cookie(f"{k}={v}; Path=/", target_url)
            return True

        if self.solver is not None:
            state = self.solver(target_url, resp)
            if inspect.isawaitable(state):
                state = run_coroutine_sync(state)  # type: ignore[arg-type]
            if isinstance(state, dict):
                self.load_storage_state(state)
                return True

        if self.flare_solverr_url:
            fs_resp = self.post(
                self.flare_solverr_url,
                json={"cmd": "request.get", "url": target_url, "maxTimeout": 60000},
            )
            if fs_resp.status_code == 200:
                sol = fs_resp.json().get("solution", {})
                self.load_storage_state(
                    {"cookies": sol.get("cookies", []), "user_agent": sol.get("userAgent")}
                )
                return True
        return False

    def gather(
        self,
        urls_or_specs: Sequence[Union[str, Dict[str, Any]]],
        concurrency: int = 50,
        **common_kwargs: Any,
    ) -> List[Response]:
        """Execute a batch of requests in parallel on the Rust Tokio runtime without writing async/await.

        Accepts URLs `["/a", "/b"]` or dicts `[{"method": "POST", "url": "/a", "json": {...}}]`.
        Returns `List[Response]` in the exact input order.
        """
        if self._mode != "rust":
            return [
                self.request(
                    spec.get("method", "GET") if isinstance(spec, dict) else common_kwargs.get("method", "GET"),
                    spec["url"] if isinstance(spec, dict) else spec,
                    **{**common_kwargs, **(spec if isinstance(spec, dict) else {})},
                )
                for spec in urls_or_specs
            ]

        auth_obj = _coerce_auth(common_kwargs.get("auth", self.auth))
        native_specs: List[Dict[str, Any]] = []
        meta_list: List[Tuple[str, str, Optional[Dict[str, str]]]] = []

        for item in urls_or_specs:
            if isinstance(item, str):
                spec = dict(common_kwargs)
                method = str(spec.pop("method", "GET"))
                raw_url = item
            else:
                spec = {**common_kwargs, **item}
                method = str(spec.pop("method", "GET"))
                raw_url = str(spec.pop("url"))

            full_url = self._resolve_url(raw_url)
            item_proxy = spec.get("proxy") or (self._next_pool_proxy() if not spec.get("proxies") else None)
            item_auth = _coerce_auth(spec["auth"]) if "auth" in spec else auth_obj
            args = self._build_native_args(
                method=method,
                url=full_url,
                params=spec.get("params"),
                headers=spec.get("headers"),
                cookies=spec.get("cookies"),
                data=spec.get("data"),
                json=spec.get("json"),
                files=spec.get("files"),
                timeout=spec.get("timeout"),
                verify=spec.get("verify"),
                proxies=spec.get("proxies"),
                proxy=item_proxy,
                allow_redirects=spec.get("allow_redirects", spec.get("follow_redirects")),
                auth_obj=item_auth,
                header_order=spec.get("header_order"),
                impersonate_override=spec.get("impersonate"),
                local_address=spec.get("local_address"),
            )
            native_specs.append(args)
            meta_list.append((method, full_url, args.get("headers")))

        try:
            natives = self._session.gather(native_specs, concurrency=max(1, int(concurrency)))
        except (RuntimeError, OSError) as exc:
            raise _translate_error(exc) from exc

        out: List[Response] = []
        for (m, u, h), nat in zip(meta_list, natives):
            resp = self._wrap_native(nat, stream=False, is_async=False)
            self._record_har_entry(m, u, h, resp)
            if self.event_hooks["response"]:
                self._run_sync_hooks("response", resp)
            out.append(resp)
        return out

    def _build_native_args(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]],
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]],
        data: Optional[Union[bytes, str, Dict[str, Any]]],
        json: Optional[Any],
        files: Any,
        timeout: Union[float, int, Tuple[Optional[float], Optional[float]], TimeoutConfig, None],
        verify: Optional[Union[bool, str]],
        proxies: Optional[Dict[str, str]],
        proxy: Optional[str],
        allow_redirects: Optional[bool],
        auth_obj: Optional[AuthBase],
        header_order: Optional[Sequence[str]],
        impersonate_override: Optional[str],
        local_address: Optional[str],
    ) -> Dict[str, Any]:
        req_headers = dict(self.headers.items())
        if headers:
            req_headers.update(headers)

        merged_params: Optional[Dict[str, str]] = None
        if self.params or params:
            mp: Dict[str, Any] = dict(self.params)
            if params:
                mp.update(params)
            merged_params = {str(k): str(v) for k, v in mp.items()}

        req_cookies = self.cookies.unscoped_for_url(url, cookies)

        if auth_obj is not None and not isinstance(auth_obj, DigestAuth):
            auth_obj.apply(req_headers)

        actual_proxy = _extract_proxy(proxy, proxies) or _extract_proxy(None, self.proxies)
        if timeout is None:
            actual_timeout = self.timeout
        else:
            actual_timeout, _, _ = _unpack_timeout(timeout)
        redirects = self.allow_redirects if allow_redirects is None else allow_redirects

        mp_files = _normalize_files(files)
        body: Optional[bytes] = None
        if mp_files is not None:
            if isinstance(data, dict):
                for k, v in data.items():
                    mp_files.append((str(k), None, str(v).encode("utf-8"), None))
        elif isinstance(data, dict):
            body = urlencode(data, doseq=True).encode("utf-8")
            if not any(k.lower() == "content-type" for k in req_headers):
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif isinstance(data, str):
            body = data.encode("utf-8")
        elif data is not None:
            body = bytes(data)

        verify_flag: Optional[bool] = None
        ca_bytes: Optional[bytes] = None
        if verify is not None:
            v_bool, ca_path = _split_verify(verify)
            verify_flag = v_bool
            if ca_path:
                ca_bytes = _read_file(ca_path)

        return dict(
            method=method,
            url=url,
            params=merged_params,
            headers=req_headers or None,
            cookies=req_cookies,
            data=body,
            json=_json.dumps(json) if json is not None else None,
            files=mp_files,
            timeout=actual_timeout,
            proxy=actual_proxy,
            allow_redirects=redirects,
            verify=verify_flag,
            ca_bundle=ca_bytes,
            header_order=list(header_order) if header_order else None,
            impersonate=str(impersonate_override) if impersonate_override else None,
            local_address=local_address,
        )

    def _wrap_native(self, native: Any, stream: bool, is_async: bool = False) -> Response:
        jar_entries = (
            self._session.all_cookies()
            if (self._mode == "rust" and hasattr(self._session, "all_cookies"))
            else None
        )
        self.cookies._sync_from_response(native.cookies, jar_entries)
        hist = _build_history_responses(getattr(native, "history", ()))
        peer_cert = getattr(native, "peer_certificate", None)
        common = dict(
            status_code=native.status_code,
            headers=native.headers,
            url=native.url,
            elapsed=native.elapsed,
            cookies=native.cookies,
            http_version=getattr(native, "http_version", "HTTP/1.1"),
            remote_addr=getattr(native, "remote_addr", None),
            peer_certificate=bytes(peer_cert) if peer_cert is not None else None,
            history=hist,
        )
        if stream:
            return Response(
                content=None,
                encoding=native.encoding or "utf-8",
                raw_chunks=None if is_async else _native_chunks(native),
                async_stream=native if is_async else None,
                closer=native.close,
                **common,
            )
        return Response(content=native.content, text=native.text, encoding=native.encoding, **common)

    def _should_retry_resp(self, resp: Response) -> bool:
        if resp.status_code in self.retry_statuses:
            return True
        if self.retry_on_challenge and resp.challenge is not None:
            return True
        return False

    def _backoff_delay(self, attempt: int) -> float:
        base = self.retry_backoff * (2 ** attempt)
        return base * (0.8 + 0.4 * _random.random())

    def _run_sync_hooks(self, kind: str, payload: Any) -> None:
        for hook in self.event_hooks.get(kind, ()):
            hook(payload)

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        data: Optional[Union[bytes, str, Dict[str, Any]]] = None,
        json: Optional[Any] = None,
        files: Any = None,
        timeout: Union[float, int, Tuple[Optional[float], Optional[float]], TimeoutConfig, None] = None,
        verify: Optional[Union[bool, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        allow_redirects: Optional[bool] = None,
        follow_redirects: Optional[bool] = None,
        auth: Optional[Union[Tuple[str, str], AuthBase]] = None,
        header_order: Optional[Sequence[str]] = None,
        impersonate: Optional[Union[str, BrowserType]] = None,
        local_address: Optional[str] = None,
        fetch_mode: Optional[str] = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Response:
        if allow_redirects is None and follow_redirects is not None:
            allow_redirects = follow_redirects
        full_url = self._resolve_url(url)
        auth_obj = _coerce_auth(auth if auth is not None else self.auth)
        req_headers = dict(headers) if headers else {}
        _apply_fetch_headers(
            req_headers,
            fetch_mode if fetch_mode is not None else self.fetch_mode,
            self._last_url if self.auto_referer else None,
        )

        # Request hooks receive a mutable context dict
        if self.event_hooks["request"]:
            ctx: Dict[str, Any] = {"method": method, "url": full_url, "headers": req_headers, "params": params}
            self._run_sync_hooks("request", ctx)
            method, full_url, req_headers, params = ctx["method"], ctx["url"], ctx["headers"], ctx["params"]

        resp: Optional[Response] = None
        if self.transport is not None:
            merged_hdrs = dict(self.headers.items())
            merged_hdrs.update(req_headers)
            resp = self.transport.handle_request(
                {
                    "method": method.upper(),
                    "url": full_url,
                    "headers": merged_hdrs,
                    "params": {**self.params, **(params or {})} or None,
                    "cookies": {**dict(self.cookies), **(cookies or {})} or None,
                    "data": data,
                    "json": json,
                }
            )
            self.cookies.update(resp.cookies)
            self._last_url = resp.url or full_url
            self._record_har_entry(method, full_url, req_headers, resp)
            if self.event_hooks["response"]:
                self._run_sync_hooks("response", resp)
            return resp

        max_attempts = 1 if stream else (1 + self.retries)
        last_exc: Optional[BaseException] = None

        for attempt in range(max_attempts):
            attempt_proxy = proxy or (self._next_pool_proxy() if not proxies else None)
            attempt_imp = str(impersonate) if impersonate else (
                "weighted_random" if (attempt > 0 and (self.rotate_impersonate or self.retry_on_challenge)) else None
            )
            try:
                if self._mode == "curl_cffi":
                    resp = self._request_cffi(
                        method, full_url, params, req_headers, cookies, data, json, files, timeout,
                        verify, proxies, attempt_proxy, allow_redirects, auth_obj, stream, kwargs,
                    )
                else:
                    args = self._build_native_args(
                        method, full_url, params, req_headers, cookies, data, json, files,
                        timeout, verify, proxies, attempt_proxy, allow_redirects, auth_obj,
                        header_order, attempt_imp, local_address,
                    )
                    call = self._session.request_stream if stream else self._session.request
                    resp = self._wrap_native(call(**args), stream=stream, is_async=False)

                # RFC 7616 DigestAuth automatic 401 handshake
                if isinstance(auth_obj, DigestAuth) and resp.status_code == 401:
                    www = resp.headers.get("www-authenticate", "")
                    chal = auth_obj.parse_challenge(www)
                    if chal is not None:
                        digest_hdrs = dict(req_headers)
                        digest_hdrs["Authorization"] = auth_obj.build_header(method, resp.url, chal)
                        args = self._build_native_args(
                            method, full_url, params, digest_hdrs, cookies, data, json, files,
                            timeout, verify, proxies, attempt_proxy, allow_redirects, None,
                            header_order, attempt_imp, local_address,
                        )
                        call = self._session.request_stream if stream else self._session.request
                        resp = self._wrap_native(call(**args), stream=stream, is_async=False)

                if attempt + 1 < max_attempts and self._should_retry_resp(resp):
                    if resp.challenge is not None or _try_extract_inline_cookie(resp.text):
                        try:
                            self.solve_challenge(resp)
                        except Exception:
                            pass
                    _time.sleep(self._backoff_delay(attempt))
                    continue
                break
            except RequestException as exc:
                last_exc = exc
                if attempt + 1 < max_attempts and isinstance(exc, (Timeout, ConnectionError)):
                    _time.sleep(self._backoff_delay(attempt))
                    continue
                raise
            except (RuntimeError, OSError) as exc:
                mapped = _translate_error(exc)
                last_exc = mapped
                if attempt + 1 < max_attempts and isinstance(mapped, (Timeout, ConnectionError)):
                    _time.sleep(self._backoff_delay(attempt))
                    continue
                raise mapped from exc
            except Exception as exc:
                if type(exc).__module__.startswith("curl_cffi"):
                    raise _translate_error(exc) from exc
                raise

        assert resp is not None, last_exc
        self._last_url = resp.url or full_url
        self._record_har_entry(method, full_url, req_headers, resp)
        if self.event_hooks["response"]:
            self._run_sync_hooks("response", resp)
        return resp

    def _request_cffi(
        self, method, url, params, headers, cookies, data, json, files, timeout,
        verify, proxies, proxy, allow_redirects, auth_obj, stream, extra
    ) -> Response:
        req_headers = dict(self.headers.items())
        if headers:
            req_headers.update(headers)

        merged_params: Optional[Dict[str, str]] = None
        if self.params or params:
            mp: Dict[str, Any] = dict(self.params)
            if params:
                mp.update(params)
            merged_params = {str(k): str(v) for k, v in mp.items()}
        req_cookies = dict(self.cookies)
        if cookies:
            req_cookies.update(cookies)
        if auth_obj is not None and not isinstance(auth_obj, DigestAuth):
            auth_obj.apply(req_headers)
        actual_proxy = _extract_proxy(proxy, proxies) or _extract_proxy(None, self.proxies)
        extra = dict(extra)
        if self.cert is not None:
            extra.setdefault("cert", self.cert)
        if files is not None:
            extra["files"] = files
        r = self._session.request(
            method=method.upper(),
            url=url,
            params=merged_params,
            headers=req_headers,
            cookies=req_cookies,
            data=data,
            json=json,
            timeout=timeout if timeout is not None else self.timeout,
            proxies={"all": actual_proxy, "http": actual_proxy, "https": actual_proxy} if actual_proxy else None,
            verify=self.verify if verify is None else verify,
            allow_redirects=self.allow_redirects if allow_redirects is None else allow_redirects,
            stream=stream,
            **extra,
        )
        got: Dict[str, str] = {}
        for source in (getattr(self._session.cookies, "jar", None), getattr(r.cookies, "jar", None)):
            try:
                for c in source or ():
                    got[c.name] = c.value
            except Exception:
                pass
        self.cookies.update(got)
        common: Dict[str, Any] = dict(
            status_code=r.status_code,
            headers=dict(r.headers),
            url=str(r.url),
            encoding=r.encoding or "utf-8",
            elapsed=getattr(r, "elapsed", 0.0),
            cookies=got,
        )
        if stream:
            return Response(content=None, raw_chunks=iter(r.iter_content()), closer=r.close, **common)
        return Response(content=r.content, text=r.text, **common)

    def ws_connect(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        proxies: Optional[Dict[str, str]] = None,
        verify: Optional[bool] = None,
    ) -> WebSocket:
        if self._mode != "rust":
            raise RuntimeError("ws_connect requires the native Rust BoringSSL engine")
        full_url = self._resolve_url(url)
        req_headers = dict(self.headers.items())
        if headers:
            req_headers.update(headers)
        actual_proxy = _extract_proxy(proxy, proxies) or _extract_proxy(None, self.proxies) or self._next_pool_proxy()
        try:
            native = self._session.ws_connect(
                url=full_url,
                headers=req_headers or None,
                proxy=actual_proxy,
                verify=verify,
            )
            return WebSocket(native)
        except RuntimeError as exc:
            raise _translate_error(exc) from exc

    def get(self, url: str, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Response:
        return self.request("DELETE", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> Response:
        return self.request("PATCH", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        kwargs.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:
        return self.request("OPTIONS", url, **kwargs)

    @contextmanager
    def stream(self, method: str, url: str, **kwargs: Any) -> Iterator[Response]:
        """Context-manager streaming request (httpx & curl_cffi compatible)."""
        kwargs["stream"] = True
        resp = self.request(method, url, **kwargs)
        try:
            yield resp
        finally:
            resp.close()

    @property
    def is_closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._closed = True
        if hasattr(self._session, "close"):
            self._session.close()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class AsyncSession:
    """Native Tokio asynchronous HTTP Session (zero thread-pool bottleneck)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._sync_session = Session(*args, **kwargs)

    @property
    def mode(self) -> str:
        return self._sync_session.mode

    @property
    def impersonate(self) -> str:
        return self._sync_session.impersonate

    def set_impersonate(self, preset: Union[str, BrowserType]) -> None:
        self._sync_session.set_impersonate(preset)

    @property
    def headers(self) -> CaseInsensitiveDict:
        return self._sync_session.headers

    @property
    def cookies(self) -> Cookies:
        return self._sync_session.cookies

    @property
    def params(self) -> Dict[str, Any]:
        return self._sync_session.params

    @property
    def is_closed(self) -> bool:
        return self._sync_session.is_closed

    def clear_cookies(self) -> None:
        self._sync_session.clear_cookies()

    async def solve_challenge(self, url_or_resp: Union[str, Response]) -> bool:
        """Asynchronously attempt to solve an anti-bot challenge and inject clearance into this AsyncSession."""
        s = self._sync_session
        if isinstance(url_or_resp, Response):
            resp = url_or_resp
            target_url = resp.url
        else:
            target_url = s._resolve_url(url_or_resp)
            resp = await self.get(target_url)

        inline = _try_extract_inline_cookie(resp.text)
        if inline:
            s.cookies.update(inline)
            if s._mode == "rust":
                for k, v in inline.items():
                    s._session.add_raw_cookie(f"{k}={v}; Path=/", target_url)
            return True

        if s.solver is not None:
            asolve = getattr(s.solver, "asolve", None)
            if callable(asolve):
                state = await asolve(target_url, resp)
            else:
                state = s.solver(target_url, resp)
                if inspect.isawaitable(state):
                    state = await state
            if isinstance(state, dict):
                s.load_storage_state(state)
                return True

        if s.flare_solverr_url:
            fs_resp = await self.post(
                s.flare_solverr_url,
                json={"cmd": "request.get", "url": target_url, "maxTimeout": 60000},
            )
            if fs_resp.status_code == 200:
                sol = fs_resp.json().get("solution", {})
                s.load_storage_state(
                    {"cookies": sol.get("cookies", []), "user_agent": sol.get("userAgent")}
                )
                return True
        return False

    def load_storage_state(
        self,
        state: Union[str, Dict[str, Any]],
        sync_impersonate: bool = True,
    ) -> Dict[str, Any]:
        return self._sync_session.load_storage_state(state, sync_impersonate=sync_impersonate)

    def save_storage_state(self, path: Optional[str] = None) -> Dict[str, Any]:
        return self._sync_session.save_storage_state(path)

    def export_har(self, path: Optional[str] = None) -> Dict[str, Any]:
        return self._sync_session.export_har(path)

    def clear_har(self) -> None:
        self._sync_session.clear_har()

    async def _run_async_hooks(self, kind: str, payload: Any) -> None:
        for hook in self._sync_session.event_hooks.get(kind, ()):
            res = hook(payload)
            if inspect.isawaitable(res):
                await res

    async def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        data: Optional[Union[bytes, str, Dict[str, Any]]] = None,
        json: Optional[Any] = None,
        files: Any = None,
        timeout: Union[float, int, Tuple[Optional[float], Optional[float]], TimeoutConfig, None] = None,
        verify: Optional[Union[bool, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        allow_redirects: Optional[bool] = None,
        follow_redirects: Optional[bool] = None,
        auth: Optional[Union[Tuple[str, str], AuthBase]] = None,
        header_order: Optional[Sequence[str]] = None,
        impersonate: Optional[Union[str, BrowserType]] = None,
        local_address: Optional[str] = None,
        fetch_mode: Optional[str] = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Response:
        if allow_redirects is None and follow_redirects is not None:
            allow_redirects = follow_redirects
        s = self._sync_session
        if s._mode != "rust" and s.transport is None:
            return await asyncio.to_thread(
                s.request, method, url, params=params, headers=headers, cookies=cookies,
                data=data, json=json, files=files, timeout=timeout, verify=verify,
                proxies=proxies, proxy=proxy, allow_redirects=allow_redirects,
                auth=auth, fetch_mode=fetch_mode, stream=stream, **kwargs,
            )

        full_url = s._resolve_url(url)
        auth_obj = _coerce_auth(auth if auth is not None else s.auth)
        req_headers = dict(headers) if headers else {}
        _apply_fetch_headers(
            req_headers,
            fetch_mode if fetch_mode is not None else s.fetch_mode,
            s._last_url if s.auto_referer else None,
        )

        if s.event_hooks["request"]:
            ctx: Dict[str, Any] = {"method": method, "url": full_url, "headers": req_headers, "params": params}
            await self._run_async_hooks("request", ctx)
            method, full_url, req_headers, params = ctx["method"], ctx["url"], ctx["headers"], ctx["params"]

        resp: Optional[Response] = None
        if s.transport is not None:
            merged_hdrs = dict(s.headers.items())
            merged_hdrs.update(req_headers)
            resp = await s.transport.handle_async_request(
                {
                    "method": method.upper(),
                    "url": full_url,
                    "headers": merged_hdrs,
                    "params": {**s.params, **(params or {})} or None,
                    "cookies": {**dict(s.cookies), **(cookies or {})} or None,
                    "data": data,
                    "json": json,
                }
            )
            s.cookies.update(resp.cookies)
            s._last_url = resp.url or full_url
            s._record_har_entry(method, full_url, req_headers, resp)
            if s.event_hooks["response"]:
                await self._run_async_hooks("response", resp)
            return resp

        max_attempts = 1 if stream else (1 + s.retries)

        for attempt in range(max_attempts):
            attempt_proxy = proxy or (s._next_pool_proxy() if not proxies else None)
            attempt_imp = str(impersonate) if impersonate else (
                "weighted_random" if (attempt > 0 and (s.rotate_impersonate or s.retry_on_challenge)) else None
            )
            try:
                args = s._build_native_args(
                    method, full_url, params, req_headers, cookies, data, json, files,
                    timeout, verify, proxies, attempt_proxy, allow_redirects, auth_obj,
                    header_order, attempt_imp, local_address,
                )
                call = s._session.async_request_stream if stream else s._session.async_request
                resp = s._wrap_native(await call(**args), stream=stream, is_async=True)

                if isinstance(auth_obj, DigestAuth) and resp.status_code == 401:
                    www = resp.headers.get("www-authenticate", "")
                    chal = auth_obj.parse_challenge(www)
                    if chal is not None:
                        digest_hdrs = dict(req_headers)
                        digest_hdrs["Authorization"] = auth_obj.build_header(method, resp.url, chal)
                        args = s._build_native_args(
                            method, full_url, params, digest_hdrs, cookies, data, json, files,
                            timeout, verify, proxies, attempt_proxy, allow_redirects, None,
                            header_order, attempt_imp, local_address,
                        )
                        call = s._session.async_request_stream if stream else s._session.async_request
                        resp = s._wrap_native(await call(**args), stream=stream, is_async=True)

                if attempt + 1 < max_attempts and s._should_retry_resp(resp):
                    if resp.challenge is not None or _try_extract_inline_cookie(resp.text):
                        try:
                            await self.solve_challenge(resp)
                        except Exception:
                            pass
                    await asyncio.sleep(s._backoff_delay(attempt))
                    continue
                break
            except RequestException as exc:
                if attempt + 1 < max_attempts and isinstance(exc, (Timeout, ConnectionError)):
                    await asyncio.sleep(s._backoff_delay(attempt))
                    continue
                raise
            except (RuntimeError, OSError) as exc:
                mapped = _translate_error(exc)
                if attempt + 1 < max_attempts and isinstance(mapped, (Timeout, ConnectionError)):
                    await asyncio.sleep(s._backoff_delay(attempt))
                    continue
                raise mapped from exc

        assert resp is not None
        s._last_url = resp.url or full_url
        s._record_har_entry(method, full_url, req_headers, resp)
        if s.event_hooks["response"]:
            await self._run_async_hooks("response", resp)
        return resp

    async def ws_connect(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        proxies: Optional[Dict[str, str]] = None,
        verify: Optional[bool] = None,
    ) -> AsyncWebSocket:
        s = self._sync_session
        if s._mode != "rust":
            raise RuntimeError("ws_connect requires the native Rust BoringSSL engine")
        full_url = s._resolve_url(url)
        req_headers = dict(s.headers.items())
        if headers:
            req_headers.update(headers)
        actual_proxy = _extract_proxy(proxy, proxies) or _extract_proxy(None, s.proxies) or s._next_pool_proxy()
        try:
            native = await s._session.async_ws_connect(
                url=full_url,
                headers=req_headers or None,
                proxy=actual_proxy,
                verify=verify,
            )
            return AsyncWebSocket(native)
        except RuntimeError as exc:
            raise _translate_error(exc) from exc

    async def get(self, url: str, **kwargs: Any) -> Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> Response:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> Response:
        return await self.request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> Response:
        return await self.request("PATCH", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Response:
        kwargs.setdefault("allow_redirects", False)
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> Response:
        return await self.request("OPTIONS", url, **kwargs)

    @asynccontextmanager
    async def stream(self, method: str, url: str, **kwargs: Any) -> AsyncIterator[Response]:
        """Async context-manager streaming request (httpx & curl_cffi compatible)."""
        kwargs["stream"] = True
        resp = await self.request(method, url, **kwargs)
        try:
            yield resp
        finally:
            await resp.aclose()

    async def aclose(self) -> None:
        """Close the async client (httpx compatible)."""
        self._sync_session.close()

    async def close(self) -> None:
        self._sync_session.close()

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._sync_session.close()


_SESSION_KEYS = (
    "timeout", "connect_timeout", "read_timeout", "verify", "proxies", "proxy", "proxies_pool",
    "allow_redirects", "follow_redirects", "auth", "cert", "header_order", "tls_options", "ja3",
    "http2_options", "akamai_h2", "http1_only", "http2_only", "resolve", "local_address", "interface",
    "tls_info", "keylog_file", "system_dns", "limits", "tcp_nodelay", "tcp_keepalive",
    "auto_referer", "fetch_mode", "transport", "retries", "retry_backoff", "retry_statuses",
    "retry_on_challenge", "rotate_impersonate", "event_hooks", "engine",
)
_REQ_SKIP_KEYS = {
    "engine", "cert", "tls_options", "ja3", "http2_options", "akamai_h2", "http1_only", "http2_only",
    "resolve", "interface", "tls_info", "keylog_file", "system_dns", "limits", "tcp_nodelay",
    "tcp_keepalive", "auto_referer", "transport", "connect_timeout", "read_timeout", "proxies_pool",
    "retries", "retry_backoff", "retry_statuses", "retry_on_challenge", "rotate_impersonate",
    "event_hooks",
}


def request(method: str, url: str, impersonate: Union[str, BrowserType] = "chrome_149", **kwargs: Any) -> Response:
    session_kw = {k: kwargs[k] for k in _SESSION_KEYS if k in kwargs and kwargs[k] is not None}
    s = Session(impersonate=impersonate, **session_kw)
    stream = bool(kwargs.get("stream"))
    try:
        resp = s.request(method, url, **{k: v for k, v in kwargs.items() if k not in _REQ_SKIP_KEYS})
    except BaseException:
        s.close()
        raise
    if stream:
        inner = resp._closer

        def _close_both() -> None:
            try:
                if inner:
                    inner()
            finally:
                s.close()

        resp._closer = _close_both
    else:
        s.close()
    return resp


def get(url: str, impersonate: Union[str, BrowserType] = "chrome_149", **kwargs: Any) -> Response:
    return request("GET", url, impersonate=impersonate, **kwargs)


def post(url: str, impersonate: Union[str, BrowserType] = "chrome_149", **kwargs: Any) -> Response:
    return request("POST", url, impersonate=impersonate, **kwargs)


def put(url: str, impersonate: Union[str, BrowserType] = "chrome_149", **kwargs: Any) -> Response:
    return request("PUT", url, impersonate=impersonate, **kwargs)


def delete(url: str, impersonate: Union[str, BrowserType] = "chrome_149", **kwargs: Any) -> Response:
    return request("DELETE", url, impersonate=impersonate, **kwargs)


def patch(url: str, impersonate: Union[str, BrowserType] = "chrome_149", **kwargs: Any) -> Response:
    return request("PATCH", url, impersonate=impersonate, **kwargs)


def head(url: str, impersonate: Union[str, BrowserType] = "chrome_149", **kwargs: Any) -> Response:
    kwargs.setdefault("allow_redirects", False)
    return request("HEAD", url, impersonate=impersonate, **kwargs)


def options(url: str, impersonate: Union[str, BrowserType] = "chrome_149", **kwargs: Any) -> Response:
    return request("OPTIONS", url, impersonate=impersonate, **kwargs)


@contextmanager
def stream(
    method: str, url: str, impersonate: Union[str, BrowserType] = "chrome_149", **kwargs: Any
) -> Iterator[Response]:
    """Top-level context-manager streaming request (httpx.stream compatible)."""
    kwargs["stream"] = True
    resp = request(method, url, impersonate=impersonate, **kwargs)
    try:
        yield resp
    finally:
        resp.close()


def session(**kwargs: Any) -> Session:
    """Factory returning a new Session (requests.session compatible)."""
    return Session(**kwargs)


def gather(
    urls_or_specs: Sequence[Union[str, Dict[str, Any]]],
    concurrency: int = 50,
    impersonate: Union[str, BrowserType] = "chrome_149",
    **kwargs: Any,
) -> List[Response]:
    """Execute a batch of requests in parallel on the Rust Tokio runtime without async/await."""
    session_kw = {k: kwargs[k] for k in _SESSION_KEYS if k in kwargs and kwargs[k] is not None}
    req_kw = {k: v for k, v in kwargs.items() if k not in _REQ_SKIP_KEYS}
    with Session(impersonate=impersonate, **session_kw) as s:
        return s.gather(urls_or_specs, concurrency=concurrency, **req_kw)


Client = Session
AsyncClient = AsyncSession
