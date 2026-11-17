"""Drop-in compatibility module matching requests and curl_cffi.requests APIs."""

from __future__ import annotations

import asyncio
import base64
import codecs
from enum import Enum
import json as _json
import warnings
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union

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

# Native Rust engine
try:
    from http_tls._core import (
        Session as _RustSession,
        __version__,
        supported_presets as _rust_presets,
    )
except ImportError:
    _RustSession = None
    __version__ = "0.3.0"
    def _rust_presets() -> List[str]:
        return []

# Byte-exact libcurl-impersonate backend
try:
    import curl_cffi.requests as _cffi_req
    from curl_cffi.requests.session import AsyncSession as _CffiAsyncSession
    from curl_cffi.requests.session import Session as _CffiSession
    _HAS_IMPERSONATE = True
except ImportError:
    _CffiSession = None
    _CffiAsyncSession = None
    _HAS_IMPERSONATE = False


class BrowserType(str, Enum):
    """Browser presets compatible with curl_cffi BrowserType."""
    # Chrome
    chrome152 = "chrome152"
    chrome152_macos = "chrome152_macos"
    chrome151 = "chrome151"
    chrome151_macos = "chrome151_macos"
    chrome150 = "chrome150"
    chrome146 = "chrome146"
    chrome145 = "chrome145"
    chrome142 = "chrome142"
    chrome136 = "chrome136"
    chrome133 = "chrome133"
    chrome131 = "chrome131"
    chrome131_android = "chrome131_android"
    chrome130 = "chrome130"
    chrome128 = "chrome128"
    chrome126 = "chrome126"
    chrome124 = "chrome124"
    chrome120 = "chrome120"
    chrome119 = "chrome119"
    chrome116 = "chrome116"
    chrome110 = "chrome110"
    chrome104 = "chrome104"
    chrome100 = "chrome100"
    chrome99 = "chrome99"
    # Edge
    edge152 = "edge152"
    edge142 = "edge142"
    edge131 = "edge131"
    edge128 = "edge128"
    edge124 = "edge124"
    edge101 = "edge101"
    edge99 = "edge99"
    # Safari
    safari27 = "safari27"
    safari26 = "safari26"
    safari184 = "safari184"
    safari180 = "safari180"
    safari18 = "safari18"
    safari170 = "safari170"
    safari17 = "safari17"
    safari155 = "safari155"
    # Firefox
    firefox155 = "firefox155"
    firefox154 = "firefox154"
    firefox153 = "firefox153"
    firefox147 = "firefox147"
    firefox144 = "firefox144"
    firefox135 = "firefox135"
    firefox133 = "firefox133"
    firefox130 = "firefox130"
    # Tor
    tor145 = "tor145"

    def __str__(self) -> str:
        return self.value


_PRESET_MAP = {
    "chrome_152": "chrome152",
    "chrome_152_macos": "chrome152_macos",
    "chrome_151": "chrome151",
    "chrome_151_macos": "chrome151_macos",
    "chrome_150": "chrome150",
    "chrome_146": "chrome146",
    "chrome_145": "chrome145",
    "chrome_142": "chrome142",
    "chrome_136": "chrome136",
    "chrome_133": "chrome133a",
    "chrome_131": "chrome131",
    "chrome_131_android": "chrome131_android",
    "chrome_130": "chrome131",
    "chrome_128": "chrome124",
    "chrome_126": "chrome124",
    "chrome_124": "chrome124",
    "edge_152": "chrome152",
    "edge_142": "chrome142",
    "edge_131": "chrome131",
    "edge_128": "chrome124",
    "edge_124": "chrome124",
    "safari_27": "safari270",
    "safari_26": "safari260",
    "safari_18_4": "safari184",
    "safari_18": "safari180",
    "safari_17": "safari170",
    "firefox_155": "firefox155",
    "firefox_154": "firefox154",
    "firefox_153": "firefox153",
    "firefox_147": "firefox147",
    "firefox_144": "firefox144",
    "firefox_135": "firefox135",
    "firefox_133": "firefox133",
    "firefox_130": "firefox133",
    "tor_14_5": "tor145",
}


def _resolve_target(preset: Union[str, BrowserType]) -> str:
    key = str(preset).lower().replace("-", "_")
    return _PRESET_MAP.get(key, key.replace("_", ""))


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
    """Map native "[kind] msg" errors and curl_cffi errors onto requests-style exceptions."""
    msg = str(exc)
    if msg.startswith("[") and "]" in msg:
        kind, _, rest = msg[1:].partition("]")
        cls = _ERROR_KINDS.get(kind)
        if cls is not None:
            return cls(rest.strip())
    # curl_cffi exceptions: walk the MRO (e.g. CertificateVerifyError -> SSLError).
    mro = [k.__name__ for k in type(exc).__mro__]
    for cls in (ConnectTimeout, ReadTimeout, SSLError, TooManyRedirects, Timeout, ConnectionError):
        if cls.__name__ in mro:
            return cls(msg)
    if any("Certificate" in n or "SSL" in n for n in mro):
        return SSLError(msg)
    if any("Timeout" in n for n in mro):
        return Timeout(msg)
    return RequestException(msg)


_FALLBACK_WARNED = False


def _warn_fallback() -> None:
    global _FALLBACK_WARNED
    if not _FALLBACK_WARNED:
        _FALLBACK_WARNED = True
        warnings.warn(
            "http_tls: curl_cffi not installed -> using the Rust/rustls engine. Browser headers are "
            "applied, but the TLS ClientHello is rustls, not a browser. For byte-exact browser TLS: "
            'pip install "http-tls[impersonate]"',
            RuntimeWarning,
            stacklevel=3,
        )


def _read_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _split_verify(verify: Union[bool, str, None]) -> Tuple[bool, Optional[str]]:
    """requests semantics: verify=False | True | "/path/to/ca_bundle.pem"."""
    if isinstance(verify, str):
        return True, verify
    return bool(True if verify is None else verify), None


def _identity_pem(cert: Union[str, Tuple[str, str], None]) -> Optional[bytes]:
    """cert="combined.pem" or cert=("client.crt", "client.key") -> one PEM blob (chain + key)."""
    if cert is None:
        return None
    if isinstance(cert, (tuple, list)):
        crt, key = cert
        return _read_file(crt).rstrip(b"\r\n") + b"\n" + _read_file(key)
    return _read_file(cert)


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
    """Unified Response object compatible with requests.Response.

    With stream=True the body stays on the socket until `content`, `text`,
    `iter_content()` or `iter_lines()` is touched.
    """

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
        *,
        raw_chunks: Optional[Iterator[bytes]] = None,
        closer: Optional[Callable[[], None]] = None,
    ) -> None:
        self.status_code = status_code
        self.headers = CaseInsensitiveDict(headers)
        self.url = url
        self.encoding = encoding or None
        self.elapsed = elapsed
        self.cookies = cookies or {}
        self.history: List["Response"] = []
        self._raw_chunks = raw_chunks
        self._closer = closer
        self._content: Optional[bytes] = None if raw_chunks is not None else (content or b"")
        self._text = text

    # -- body -------------------------------------------------------------
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

    # -- helpers ----------------------------------------------------------
    @property
    def ok(self) -> _OkDescriptor:
        return _OkDescriptor(200 <= self.status_code < 400)

    @property
    def reason(self) -> str:
        try:
            from http import HTTPStatus
            return HTTPStatus(self.status_code).phrase
        except ValueError:
            return ""

    @property
    def challenge(self) -> Optional[str]:
        """Edge provider name if this is a browser-verification interstitial (e.g. "cloudflare"), else None."""
        return _challenge.detect(self)

    def json(self, **kwargs: Any) -> Any:
        return _json.loads(self.text, **kwargs)

    def raise_for_status(self) -> None:
        """Raise HTTPError if the response was a client or server error (4xx/5xx)."""
        if 400 <= self.status_code < 500:
            raise HTTPError(f"{self.status_code} Client Error: {self.reason} for url: {self.url}", response=self)
        if 500 <= self.status_code < 600:
            raise HTTPError(f"{self.status_code} Server Error: {self.reason} for url: {self.url}", response=self)

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}]>"

    def __bytes__(self) -> bytes:
        return self.content


def supported_presets() -> List[str]:
    return list(_PRESET_MAP.keys())


def _native_chunks(stream: Any) -> Iterator[bytes]:
    while True:
        chunk = stream.read_chunk()
        if chunk is None:
            return
        yield chunk


class Session:
    """HTTP Session: drop-in for requests.Session and curl_cffi.requests.Session.

    verify: True | False | "/path/to/ca_bundle.pem"
    cert:   "client_combined.pem" | ("client.crt", "client.key")
    engine: "auto" (curl_cffi if installed, else Rust) | "impersonate" | "rust"
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
        if engine not in ("auto", "impersonate", "rust"):
            raise ValueError("engine must be 'auto', 'impersonate' or 'rust'")
        if engine == "impersonate" and not _HAS_IMPERSONATE:
            raise RuntimeError('engine="impersonate" requires curl_cffi: pip install "http-tls[impersonate]"')

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
        self.cookies = dict(cookies or {})
        p_val = _extract_proxy(proxy, proxies)
        self.proxies = dict(proxies) if proxies else ({"all": proxy, "http": proxy, "https": proxy} if proxy else {})

        if engine != "rust" and _HAS_IMPERSONATE:
            self._mode = "impersonate"
            self._session = _CffiSession(
                impersonate=_resolve_target(self.impersonate),
                timeout=timeout,
                max_redirects=max_redirects,
                verify=self.verify,
                proxies={"all": p_val, "http": p_val, "https": p_val} if p_val else None,
            )
        else:
            self._mode = "rust"
            if _RustSession is None:
                raise RuntimeError("Rust native engine '_core' not compiled.")
            if engine == "auto":
                _warn_fallback()
            self._session = _RustSession(
                impersonate=self.impersonate,
                timeout=timeout,
                follow_redirects=self.allow_redirects,
                max_redirects=max_redirects,
                verify_ssl=bool(self.verify),
                proxy=p_val,
                ca_bundle=_read_file(ca_path) if ca_path else None,
                client_identity=_identity_pem(cert),
            )

    @property
    def mode(self) -> str:
        """Engine actually in use: "impersonate" (curl_cffi) or "rust"."""
        return self._mode

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        data: Optional[Union[bytes, str, Dict[str, Any]]] = None,
        json: Optional[Any] = None,
        timeout: Optional[float] = None,
        verify: Optional[Union[bool, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        allow_redirects: Optional[bool] = None,
        auth: Optional[Tuple[str, str]] = None,
        stream: bool = False,
        **kwargs: Any,
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
        actual_timeout = timeout if timeout is not None else self.timeout
        redirects = self.allow_redirects if allow_redirects is None else allow_redirects

        try:
            if self._mode == "impersonate":
                return self._request_cffi(
                    method, url, params, req_headers, req_cookies, data, json, actual_timeout,
                    self.verify if verify is None else verify, actual_proxy, redirects, stream, kwargs,
                )
            return self._request_rust(
                method, url, params, req_headers, req_cookies, data, json, actual_timeout,
                verify, actual_proxy, redirects, stream,
            )
        except RequestException:
            raise
        except (RuntimeError, OSError) as exc:
            raise _translate_error(exc) from exc
        except Exception as exc:
            if type(exc).__module__.startswith("curl_cffi"):
                raise _translate_error(exc) from exc
            raise

    def _request_cffi(self, method, url, params, headers, cookies, data, json, timeout,
                      verify, proxy, redirects, stream, extra) -> Response:
        extra = dict(extra)
        if self.cert is not None:
            extra.setdefault("cert", self.cert)
        r = self._session.request(
            method=method.upper(),
            url=url,
            params=params,
            headers=headers,
            cookies=cookies,
            data=data,
            json=json,
            timeout=timeout,
            proxies={"all": proxy, "http": proxy, "https": proxy} if proxy else None,
            verify=verify,
            allow_redirects=redirects,
            stream=stream,
            **extra,
        )
        # Cookies set on intermediate redirect hops live in the curl_cffi session jar,
        # not on the final response object.
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

    def _request_rust(self, method, url, params, headers, cookies, data, json, timeout,
                      verify, proxy, redirects, stream) -> Response:
        if isinstance(verify, str):
            raise ValueError("Per-request CA bundle is not supported by the Rust engine; pass verify=path to Session()")
        if isinstance(data, dict):
            from urllib.parse import urlencode
            data = urlencode(data, doseq=True)
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        body = data.encode("utf-8") if isinstance(data, str) else data
        call = self._session.request_stream if stream else self._session.request
        native = call(
            method=method,
            url=url,
            params={k: str(v) for k, v in params.items()} if params else None,
            headers=headers,
            cookies=cookies,
            data=body,
            json=_json.dumps(json) if json is not None else None,
            timeout=timeout,
            proxy=proxy,
            allow_redirects=redirects,
            verify=None if verify is None else bool(verify),
        )
        self.cookies.update(native.cookies)
        common = dict(
            status_code=native.status_code,
            headers=native.headers,
            url=native.url,
            elapsed=native.elapsed,
            cookies=native.cookies,
        )
        if stream:
            return Response(
                content=None,
                encoding=native.encoding or "utf-8",
                raw_chunks=_native_chunks(native),
                closer=native.close,
                **common,
            )
        return Response(content=native.content, text=native.text, encoding=native.encoding, **common)

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
    """Asynchronous Session (requests / curl_cffi compatible). Requests run on worker threads;
    the Rust engine releases the GIL for the whole network round-trip."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._sync_session = Session(*args, **kwargs)

    @property
    def headers(self) -> CaseInsensitiveDict:
        return self._sync_session.headers

    @property
    def cookies(self) -> Dict[str, str]:
        return self._sync_session.cookies

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:
        return await asyncio.to_thread(self._sync_session.request, method, url, **kwargs)

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
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> Response:
        return await self.request("OPTIONS", url, **kwargs)

    async def close(self) -> None:
        self._sync_session.close()

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._sync_session.close()


_SESSION_KEYS = ("timeout", "verify", "proxies", "proxy", "allow_redirects", "auth", "cert", "engine")


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
