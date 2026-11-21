"""Drop-in compatibility module matching requests, httpx, and curl_cffi APIs.

Powered by the native Rust BoringSSL (`wreq` + `btls` + Tokio) engine for
standalone byte-exact JA3/JA4/HTTP2 emulation, native async I/O, streaming,
multipart uploads, mTLS, custom CA bundles, and TLS-impersonated WebSockets.
"""

from __future__ import annotations

import asyncio
import base64
import codecs
from enum import Enum
import json as _json
import os
import re
from typing import Any, AsyncIterator, Callable, Dict, Iterator, List, Optional, Tuple, Union
from urllib.parse import urlencode

from http_tls import challenge as _challenge
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
    __version__ = "0.4.0"

    def _rust_presets() -> List[str]:
        return []


# Optional curl_cffi backend (only used when explicitly requested via engine="curl_cffi")
try:
    from curl_cffi.requests.session import Session as _CffiSession
    _HAS_CFFI = True
except ImportError:
    _CffiSession = None
    _HAS_CFFI = False


class BrowserType(str, Enum):
    """Browser presets compatible with curl_cffi BrowserType and wreq-util Profiles."""
    # Chrome
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
    # Edge
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
    # Safari
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
    # Firefox
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
    # Opera
    opera131 = "opera_131"
    opera130 = "opera_130"
    opera128 = "opera_128"
    opera124 = "opera_124"
    opera120 = "opera_120"
    opera116 = "opera_116"
    # OkHttp
    okhttp5 = "okhttp_5"
    okhttp4_12 = "okhttp_4_12"
    okhttp4_10 = "okhttp_4_10"
    # Tor / Random
    tor145 = "tor_14_5"
    random = "random"
    weighted_random = "weighted_random"

    def __str__(self) -> str:
        return self.value


def supported_presets() -> List[str]:
    return list(_rust_presets()) or [b.value for b in BrowserType]


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
    """Map native "[kind] msg" errors and curl_cffi errors onto requests/httpx exceptions."""
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
    """Split cert="combined.pem" or cert=("client.crt", "client.key") into (cert_pem, key_pem)."""
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
    """Convert requests/httpx `files=` dict or sequence into [(field, filename, bytes, content_type)]."""
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
        if hasattr(obj, "read"):
            raw = obj.read()
        else:
            raw = obj
        payload = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
        out.append((str(field), filename, payload, content_type))
    return out


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
        self.history: List["Response"] = []
        self._raw_chunks = raw_chunks
        self._async_stream = async_stream
        self._closer = closer
        self._content: Optional[bytes] = None if (raw_chunks is not None or async_stream is not None) else (content or b"")
        self._text = text

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
                            yield chunk
                finally:
                    self.close()
                return
            raise RuntimeError("The content for this response was already consumed")
        chunks, self._raw_chunks = self._raw_chunks, None
        try:
            for chunk in chunks:
                if chunk:
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
        """Asynchronously yield body bytes (httpx compatible, native Tokio streaming)."""
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
        """Asynchronously yield decoded lines (httpx compatible)."""
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

    @property
    def reason(self) -> str:
        try:
            from http import HTTPStatus
            return HTTPStatus(self.status_code).phrase
        except ValueError:
            return ""

    @property
    def challenge(self) -> Optional[str]:
        """Edge provider name if this is a browser-verification interstitial, else None."""
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
        if msg is None:
            return None
        return msg[1].decode("utf-8", errors="replace")

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
        if res is None:
            return None
        return (res[0], bytes(res[1]))

    async def recv_text(self) -> Optional[str]:
        msg = await self.recv()
        if msg is None:
            return None
        return msg[1].decode("utf-8", errors="replace")

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


class Session:
    """HTTP Session: 100% drop-in for requests.Session, httpx.Client, and curl_cffi.requests.Session.

    engine: "auto" | "rust" | "boring" | "impersonate" (all use the standalone Rust BoringSSL engine)
            or "curl_cffi" (optional legacy curl_cffi backend if installed).
    """

    def __init__(
        self,
        impersonate: Union[str, BrowserType] = "chrome_152",
        timeout: float = 30.0,
        verify: Union[bool, str] = True,
        verify_ssl: bool = True,
        proxies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        allow_redirects: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        cert: Union[str, Tuple[str, str], None] = None,
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
        self.max_redirects = max_redirects
        self.allow_redirects = allow_redirects and follow_redirects
        self.engine = engine
        self.auth = auth

        self.headers = CaseInsensitiveDict(headers or {})
        self.cookies = Cookies(cookies, on_clear=self._clear_backend_cookies)
        p_val = _extract_proxy(proxy, proxies)
        self.proxies = dict(proxies) if proxies else ({"all": proxy, "http": proxy, "https": proxy} if proxy else {})

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
            )

    @property
    def mode(self) -> str:
        """Active engine: "rust" (native BoringSSL wreq) or "curl_cffi"."""
        return self._mode

    def _clear_backend_cookies(self) -> None:
        if self._mode == "rust":
            self._session.clear_cookies()
        elif hasattr(self._session, "cookies") and hasattr(self._session.cookies, "clear"):
            self._session.cookies.clear()

    def clear_cookies(self) -> None:
        """Clear all session cookies from memory and the native cookie jar."""
        self.cookies.clear()

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
        auth: Optional[Tuple[str, str]],
    ) -> Dict[str, Any]:
        req_headers = dict(self.headers.items())
        if headers:
            req_headers.update(headers)

        req_cookies = dict(self.cookies)
        if cookies:
            req_cookies.update(cookies)

        active_auth = auth or self.auth
        if active_auth and len(active_auth) == 2:
            token = base64.b64encode(f"{active_auth[0]}:{active_auth[1]}".encode()).decode()
            req_headers["Authorization"] = f"Basic {token}"

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
            params={k: str(v) for k, v in params.items()} if params else None,
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
        )

    def _wrap_native(self, native: Any, stream: bool, is_async: bool = False) -> Response:
        self.cookies.update(native.cookies)
        common = dict(
            status_code=native.status_code,
            headers=native.headers,
            url=native.url,
            elapsed=native.elapsed,
            cookies=native.cookies,
            http_version=getattr(native, "http_version", "HTTP/1.1"),
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
        auth: Optional[Tuple[str, str]] = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Response:
        if allow_redirects is None and follow_redirects is not None:
            allow_redirects = follow_redirects
        try:
            if self._mode == "curl_cffi":
                return self._request_cffi(
                    method, url, params, headers, cookies, data, json, files, timeout,
                    verify, proxies, proxy, allow_redirects, auth, stream, kwargs,
                )
            args = self._build_native_args(
                method, url, params, headers, cookies, data, json, files,
                timeout, verify, proxies, proxy, allow_redirects, auth,
            )
            call = self._session.request_stream if stream else self._session.request
            native = call(**args)
            return self._wrap_native(native, stream=stream, is_async=False)
        except RequestException:
            raise
        except (RuntimeError, OSError) as exc:
            raise _translate_error(exc) from exc
        except Exception as exc:
            if type(exc).__module__.startswith("curl_cffi"):
                raise _translate_error(exc) from exc
            raise

    def _request_cffi(
        self, method, url, params, headers, cookies, data, json, files, timeout,
        verify, proxies, proxy, allow_redirects, auth, stream, extra
    ) -> Response:
        req_headers = dict(self.headers.items())
        if headers:
            req_headers.update(headers)
        req_cookies = dict(self.cookies)
        if cookies:
            req_cookies.update(cookies)
        active_auth = auth or self.auth
        if active_auth and len(active_auth) == 2:
            token = base64.b64encode(f"{active_auth[0]}:{active_auth[1]}".encode()).decode()
            req_headers["Authorization"] = f"Basic {token}"
        actual_proxy = _extract_proxy(proxy, proxies) or _extract_proxy(None, self.proxies)
        extra = dict(extra)
        if self.cert is not None:
            extra.setdefault("cert", self.cert)
        if files is not None:
            extra["files"] = files
        r = self._session.request(
            method=method.upper(),
            url=url,
            params=params,
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
        """Open a synchronous TLS-impersonated WebSocket connection."""
        if self._mode != "rust":
            raise RuntimeError("ws_connect requires the native Rust BoringSSL engine")
        req_headers = dict(self.headers.items())
        if headers:
            req_headers.update(headers)
        actual_proxy = _extract_proxy(proxy, proxies) or _extract_proxy(None, self.proxies)
        try:
            native = self._session.ws_connect(
                url=url,
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

    def close(self) -> None:
        if hasattr(self._session, "close"):
            self._session.close()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class AsyncSession:
    """Native Tokio asynchronous HTTP Session (zero thread-pool bottleneck).

    100% compatible with httpx.AsyncClient and curl_cffi.requests.AsyncSession.
    """

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

    def clear_cookies(self) -> None:
        self._sync_session.clear_cookies()

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
        auth: Optional[Tuple[str, str]] = None,
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
        try:
            args = s._build_native_args(
                method, url, params, headers, cookies, data, json, files,
                timeout, verify, proxies, proxy, allow_redirects, auth,
            )
            call = s._session.async_request_stream if stream else s._session.async_request
            native = await call(**args)
            return s._wrap_native(native, stream=stream, is_async=True)
        except RequestException:
            raise
        except (RuntimeError, OSError) as exc:
            raise _translate_error(exc) from exc

    async def ws_connect(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        proxies: Optional[Dict[str, str]] = None,
        verify: Optional[bool] = None,
    ) -> AsyncWebSocket:
        """Open a native Tokio async TLS-impersonated WebSocket connection."""
        s = self._sync_session
        if s._mode != "rust":
            raise RuntimeError("ws_connect requires the native Rust BoringSSL engine")
        req_headers = dict(s.headers.items())
        if headers:
            req_headers.update(headers)
        actual_proxy = _extract_proxy(proxy, proxies) or _extract_proxy(None, s.proxies)
        try:
            native = await s._session.async_ws_connect(
                url=url,
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

    async def close(self) -> None:
        self._sync_session.close()

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._sync_session.close()


_SESSION_KEYS = ("timeout", "verify", "proxies", "proxy", "allow_redirects", "follow_redirects", "auth", "cert", "engine")


def request(method: str, url: str, impersonate: Union[str, BrowserType] = "chrome_152", **kwargs: Any) -> Response:
    """One-shot request. With stream=True the session stays open until the response is closed."""
    session_kw = {k: kwargs[k] for k in _SESSION_KEYS if k in kwargs and kwargs[k] is not None}
    s = Session(impersonate=impersonate, **session_kw)
    stream = bool(kwargs.get("stream"))
    try:
        resp = s.request(method, url, **{k: v for k, v in kwargs.items() if k not in ("engine", "cert")})
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


# httpx-compatible aliases
Client = Session
AsyncClient = AsyncSession
