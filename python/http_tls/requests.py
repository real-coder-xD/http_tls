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
from urllib.parse import urlencode, urljoin

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
from http_tls.status_codes import codes
from http_tls.structures import CaseInsensitiveDict

# Native Rust BoringSSL engine
try:
    from http_tls._core import (
        Session as _RustSession,
        WebSocket as _NativeWebSocket,
        __version__,
        supported_presets as _rust_presets,
    )
except ImportError:
    _RustSession = None
    _NativeWebSocket = None
    __version__ = "0.6.2"

    def _rust_presets() -> List[str]:
        return []


# Optional legacy curl_cffi backend (only used when explicitly requested via engine="curl_cffi")
try:
    from curl_cffi.requests.session import Session as _CffiSession
    _HAS_CFFI = True
except ImportError:
    _CffiSession = None
    _HAS_CFFI = False


class BrowserType(str, Enum):
    """Browser presets compatible with curl_cffi BrowserType and wreq-util Profiles."""
    chrome152 = "chrome_152"
    chrome152_macos = "chrome_152_macos"
    chrome151 = "chrome_151"
    chrome151_macos = "chrome_151_macos"
    chrome150 = "chrome_150"
    chrome149 = "chrome_149"
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
    edge152 = "edge_152"
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
    safari27 = "safari_27"
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
    safari170 = "safari_17"
    safari17 = "safari_17"
    safari155 = "safari_15_5"
    firefox155 = "firefox_155"
    firefox154 = "firefox_154"
    firefox153 = "firefox_153"
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


def supported_presets() -> List[str]:
    return list(_rust_presets()) or [b.value for b in BrowserType]


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
    """Dictionary of cookies with deep session synchronization."""

    def __init__(self, initial: Optional[Dict[str, str]] = None, on_clear: Optional[Callable[[], None]] = None) -> None:
        super().__init__(initial or {})
        self._on_clear = on_clear

    def clear(self) -> None:
        super().clear()
        if self._on_clear is not None:
            self._on_clear()

    def set(self, name: str, value: str, domain: Optional[str] = None, path: Optional[str] = None) -> None:
        self[name] = value

    def get(self, name: str, default: Any = None) -> Any:
        return super().get(name, default)

    def delete(self, name: str) -> None:
        if name in self:
            del self[name]

    def get_dict(self) -> Dict[str, str]:
        """Return cookies as a plain dictionary (requests & curl_cffi compatible)."""
        return dict(self)


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
        impersonate: Union[str, BrowserType] = "chrome_152",
        timeout: float = 30.0,
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

        verify_flag, ca_path = _split_verify(verify)
        self.impersonate = str(impersonate)
        self.timeout = timeout
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
        self.proxies_pool: List[str] = list(proxies_pool) if proxies_pool else []
        self._proxy_idx = 0
        self.event_hooks: Dict[str, List[Callable[..., Any]]] = {
            "request": list((event_hooks or {}).get("request", [])),
            "response": list((event_hooks or {}).get("response", [])),
        }

        self.headers = CaseInsensitiveDict(headers or {})
        self.params: Dict[str, Any] = dict(params or {})
        self.cookies = Cookies(cookies, on_clear=self._clear_backend_cookies)
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

        if engine == "curl_cffi":
            if not _HAS_CFFI:
                raise RuntimeError('engine="curl_cffi" requires curl_cffi: pip install "http-tls[curl_cffi]"')
            self._mode = "curl_cffi"
            self._session = _CffiSession(
                impersonate=self.impersonate.replace("_", ""),
                timeout=timeout,
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
                timeout=timeout,
                follow_redirects=self.allow_redirects,
                max_redirects=max_redirects,
                verify_ssl=bool(self.verify),
                proxy=p_val,
                ca_bundle=_read_file(ca_path) if ca_path else None,
                client_cert=client_cert,
                client_key=client_key,
                header_order=list(header_order) if header_order else None,
                tls_options=merged_tls,
                http2_options=dict(http2_options) if http2_options else None,
                http1_only=http1_only,
                http2_only=http2_only,
                resolve=dict(resolve) if resolve else None,
                local_address=local_address,
                interface=interface,
                tls_info=tls_info,
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
                pool_max_idle_per_host=pool_max_idle_per_host,
                pool_idle_timeout=pool_idle_timeout,
                keylog_file=keylog_file,
                system_dns=self.system_dns,
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

    def clear_cookies(self) -> None:
        self.cookies.clear()

    def load_storage_state(self, state: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Load Playwright / Camoufox `storage_state.json` (path or dict) into this Session."""
        data = _json.loads(_read_file(state).decode("utf-8")) if isinstance(state, str) else dict(state)
        ua = data.get("user_agent") or data.get("userAgent")
        if ua:
            self.headers["User-Agent"] = str(ua)
        if isinstance(data.get("headers"), dict):
            self.headers.update(data["headers"])

        raw_cookies = data.get("cookies", [])
        if isinstance(raw_cookies, dict):
            for k, v in raw_cookies.items():
                self.cookies[str(k)] = str(v)
        elif isinstance(raw_cookies, list):
            for c in raw_cookies:
                if not isinstance(c, dict) or "name" not in c or "value" not in c:
                    continue
                name, val = str(c["name"]), str(c["value"])
                self.cookies[name] = val
                if self._mode == "rust":
                    dom = str(c.get("domain") or "").lstrip(".")
                    path = str(c.get("path") or "/")
                    if dom:
                        parts = [f"{name}={val}", f"Domain={dom}", f"Path={path}"]
                        if c.get("secure"):
                            parts.append("Secure")
                        if c.get("httpOnly"):
                            parts.append("HttpOnly")
                        scheme = "https" if c.get("secure", True) else "http"
                        self._session.add_raw_cookie("; ".join(parts), f"{scheme}://{dom}{path}")
        return data

    def save_storage_state(self, path: Optional[str] = None) -> Dict[str, Any]:
        """Export current session cookies and User-Agent in Playwright `storage_state.json` format."""
        seen: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        if self._mode == "rust" and hasattr(self._session, "all_cookies"):
            for name, val, dom, cpath, sec, ho in self._session.all_cookies():
                seen[(name, dom, cpath)] = {
                    "name": name,
                    "value": val,
                    "domain": dom,
                    "path": cpath or "/",
                    "expires": -1,
                    "httpOnly": bool(ho),
                    "secure": bool(sec),
                    "sameSite": "Lax",
                }
        existing_names = {k[0] for k in seen}
        for name, val in self.cookies.items():
            if name not in existing_names:
                seen[(name, "", "/")] = {
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
        timeout: Optional[float],
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

        req_cookies = dict(self.cookies)
        if cookies:
            req_cookies.update(cookies)

        if auth_obj is not None and not isinstance(auth_obj, DigestAuth):
            auth_obj.apply(req_headers)

        actual_proxy = _extract_proxy(proxy, proxies) or _extract_proxy(None, self.proxies)
        actual_timeout = timeout if timeout is not None else self.timeout
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
            cookies=req_cookies or None,
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
        self.cookies.update(native.cookies)
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
        timeout: Optional[float] = None,
        verify: Optional[Union[bool, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        allow_redirects: Optional[bool] = None,
        follow_redirects: Optional[bool] = None,
        auth: Optional[Union[Tuple[str, str], AuthBase]] = None,
        header_order: Optional[Sequence[str]] = None,
        impersonate: Optional[Union[str, BrowserType]] = None,
        local_address: Optional[str] = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Response:
        if allow_redirects is None and follow_redirects is not None:
            allow_redirects = follow_redirects
        full_url = self._resolve_url(url)
        auth_obj = _coerce_auth(auth if auth is not None else self.auth)
        req_headers = dict(headers) if headers else {}

        # Request hooks receive a mutable context dict
        if self.event_hooks["request"]:
            ctx = {"method": method, "url": full_url, "headers": req_headers, "params": params}
            self._run_sync_hooks("request", ctx)
            method, full_url, req_headers, params = ctx["method"], ctx["url"], ctx["headers"], ctx["params"]

        max_attempts = 1 if stream else (1 + self.retries)
        last_exc: Optional[BaseException] = None
        resp: Optional[Response] = None

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
        common = dict(
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
        return await asyncio.to_thread(self._sync_session.solve_challenge, url_or_resp)

    def load_storage_state(self, state: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        return self._sync_session.load_storage_state(state)

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
        timeout: Optional[float] = None,
        verify: Optional[Union[bool, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        allow_redirects: Optional[bool] = None,
        follow_redirects: Optional[bool] = None,
        auth: Optional[Union[Tuple[str, str], AuthBase]] = None,
        header_order: Optional[Sequence[str]] = None,
        impersonate: Optional[Union[str, BrowserType]] = None,
        local_address: Optional[str] = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Response:
        if allow_redirects is None and follow_redirects is not None:
            allow_redirects = follow_redirects
        s = self._sync_session
        if s._mode != "rust":
            return await asyncio.to_thread(
                s.request, method, url, params=params, headers=headers, cookies=cookies,
                data=data, json=json, files=files, timeout=timeout, verify=verify,
                proxies=proxies, proxy=proxy, allow_redirects=allow_redirects,
                auth=auth, stream=stream, **kwargs,
            )

        full_url = s._resolve_url(url)
        auth_obj = _coerce_auth(auth if auth is not None else s.auth)
        req_headers = dict(headers) if headers else {}

        if s.event_hooks["request"]:
            ctx = {"method": method, "url": full_url, "headers": req_headers, "params": params}
            await self._run_async_hooks("request", ctx)
            method, full_url, req_headers, params = ctx["method"], ctx["url"], ctx["headers"], ctx["params"]

        max_attempts = 1 if stream else (1 + s.retries)
        resp: Optional[Response] = None

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
    "http2_options", "http1_only", "http2_only", "resolve", "local_address", "interface",
    "tls_info", "retries", "retry_backoff", "retry_statuses", "retry_on_challenge",
    "rotate_impersonate", "event_hooks", "engine",
)
_REQ_SKIP_KEYS = {
    "engine", "cert", "tls_options", "ja3", "http2_options", "http1_only", "http2_only",
    "resolve", "interface", "tls_info", "connect_timeout", "read_timeout", "proxies_pool",
    "retries", "retry_backoff", "retry_statuses", "retry_on_challenge", "rotate_impersonate",
    "event_hooks",
}


def request(method: str, url: str, impersonate: Union[str, BrowserType] = "chrome_152", **kwargs: Any) -> Response:
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


def get(url: str, impersonate: Union[str, BrowserType] = "chrome_152", **kwargs: Any) -> Response:
    return request("GET", url, impersonate=impersonate, **kwargs)


def post(url: str, impersonate: Union[str, BrowserType] = "chrome_152", **kwargs: Any) -> Response:
    return request("POST", url, impersonate=impersonate, **kwargs)


def put(url: str, impersonate: Union[str, BrowserType] = "chrome_152", **kwargs: Any) -> Response:
    return request("PUT", url, impersonate=impersonate, **kwargs)


def delete(url: str, impersonate: Union[str, BrowserType] = "chrome_152", **kwargs: Any) -> Response:
    return request("DELETE", url, impersonate=impersonate, **kwargs)


def patch(url: str, impersonate: Union[str, BrowserType] = "chrome_152", **kwargs: Any) -> Response:
    return request("PATCH", url, impersonate=impersonate, **kwargs)


def head(url: str, impersonate: Union[str, BrowserType] = "chrome_152", **kwargs: Any) -> Response:
    kwargs.setdefault("allow_redirects", False)
    return request("HEAD", url, impersonate=impersonate, **kwargs)


def options(url: str, impersonate: Union[str, BrowserType] = "chrome_152", **kwargs: Any) -> Response:
    return request("OPTIONS", url, impersonate=impersonate, **kwargs)


@contextmanager
def stream(
    method: str, url: str, impersonate: Union[str, BrowserType] = "chrome_152", **kwargs: Any
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
    impersonate: Union[str, BrowserType] = "chrome_152",
    **kwargs: Any,
) -> List[Response]:
    """Execute a batch of requests in parallel on the Rust Tokio runtime without async/await."""
    session_kw = {k: kwargs[k] for k in _SESSION_KEYS if k in kwargs and kwargs[k] is not None}
    req_kw = {k: v for k, v in kwargs.items() if k not in _REQ_SKIP_KEYS}
    with Session(impersonate=impersonate, **session_kw) as s:
        return s.gather(urls_or_specs, concurrency=concurrency, **req_kw)


Client = Session
AsyncClient = AsyncSession
