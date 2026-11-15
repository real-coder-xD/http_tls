"""Drop-in compatibility module matching requests and curl_cffi.requests APIs."""

from __future__ import annotations

import asyncio
import base64
from enum import Enum
import json as _json
from typing import Any, Dict, List, Optional, Tuple, Union

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
        Response as _NativeResponse,
        Session as _RustSession,
        __version__,
        supported_presets as _rust_presets,
    )
except ImportError:
    _RustSession = None
    _NativeResponse = None
    __version__ = "0.2.0"
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
    """Unified Response object 100% compatible with requests.Response."""

    def __init__(
        self,
        status_code: int,
        headers: Dict[str, str],
        url: str,
        content: bytes,
        text: str,
        encoding: str = "utf-8",
        elapsed: float = 0.0,
        cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        self.status_code = status_code
        self.headers = CaseInsensitiveDict(headers)
        self.url = url
        self.content = content
        self.text = text
        self.encoding = encoding
        self.elapsed = elapsed
        self.cookies = cookies or {}

    @property
    def ok(self) -> _OkDescriptor:
        return _OkDescriptor(200 <= self.status_code < 400)

    def json(self, **kwargs: Any) -> Any:
        return _json.loads(self.text, **kwargs)

    def raise_for_status(self) -> None:
        """Raise HTTPError if the response was a client or server error (4xx/5xx)."""
        if 400 <= self.status_code < 500:
            raise HTTPError(f"{self.status_code} Client Error for url: {self.url}", response=self)
        elif 500 <= self.status_code < 600:
            raise HTTPError(f"{self.status_code} Server Error for url: {self.url}", response=self)

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}]>"

    def __bytes__(self) -> bytes:
        return self.content


def supported_presets() -> List[str]:
    return list(_PRESET_MAP.keys())


class Session:
    """HTTP Session: 100% drop-in for requests.Session and curl_cffi.requests.Session."""

    def __init__(
        self,
        impersonate: Union[str, BrowserType] = "chrome_152",
        timeout: float = 30.0,
        verify: bool = True,
        verify_ssl: bool = True,
        proxies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        allow_redirects: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        engine: str = "auto",
        **kwargs: Any,
    ) -> None:
        self.impersonate = str(impersonate)
        self.timeout = timeout
        self.verify = verify and verify_ssl
        self.max_redirects = max_redirects
        self.allow_redirects = allow_redirects and follow_redirects
        self.engine = engine
        self.auth = auth

        self.headers = CaseInsensitiveDict(headers or {})
        self.cookies = dict(cookies or {})
        self.proxies = proxies or ({"all": proxy, "http": proxy, "https": proxy} if proxy else {})

        use_impersonate = (engine in ("auto", "impersonate")) and _HAS_IMPERSONATE
        if use_impersonate:
            self._mode = "impersonate"
            target = _resolve_target(self.impersonate)
            p_val = _extract_proxy(proxy, proxies)
            p_dict = {"all": p_val, "http": p_val, "https": p_val} if p_val else None
            self._session = _CffiSession(
                impersonate=target,
                timeout=timeout,
                max_redirects=max_redirects,
                verify=self.verify,
                proxies=p_dict,
            )
        else:
            self._mode = "rust"
            if _RustSession is None:
                raise RuntimeError("Rust native engine '_core' not compiled.")
            self._session = _RustSession(
                impersonate=self.impersonate,
                timeout=timeout,
                follow_redirects=self.allow_redirects,
                max_redirects=max_redirects,
                verify_ssl=self.verify,
                proxy=_extract_proxy(proxy, proxies),
            )

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        data: Optional[Union[bytes, str]] = None,
        json: Optional[Any] = None,
        timeout: Optional[float] = None,
        verify: Optional[bool] = None,
        proxies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        allow_redirects: Optional[bool] = None,
        auth: Optional[Tuple[str, str]] = None,
        **kwargs: Any,
    ) -> Response:
        # Merge headers
        req_headers = dict(self.headers.items())
        if headers:
            req_headers.update(headers)

        # Merge cookies
        req_cookies = dict(self.cookies)
        if cookies:
            req_cookies.update(cookies)

        # Basic Auth
        active_auth = auth or self.auth
        if active_auth and len(active_auth) == 2:
            auth_str = f"{active_auth[0]}:{active_auth[1]}"
            b64_auth = base64.b64encode(auth_str.encode()).decode()
            req_headers["Authorization"] = f"Basic {b64_auth}"

        actual_proxy = _extract_proxy(proxy, proxies) or _extract_proxy(None, self.proxies)
        actual_timeout = timeout if timeout is not None else self.timeout

        if self._mode == "impersonate":
            p_dict = {"all": actual_proxy, "http": actual_proxy, "https": actual_proxy} if actual_proxy else None
            cffi_resp = self._session.request(
                method=method.upper(),
                url=url,
                params=params,
                headers=req_headers,
                cookies=req_cookies,
                data=data,
                json=json,
                timeout=actual_timeout,
                proxies=p_dict,
                verify=self.verify if verify is None else verify,
                allow_redirects=self.allow_redirects if allow_redirects is None else allow_redirects,
                **kwargs,
            )
            raw_cookies = {}
            try:
                raw_cookies = dict(cffi_resp.cookies)
                self.cookies.update(raw_cookies)
            except Exception:
                pass
            return Response(
                status_code=cffi_resp.status_code,
                headers=dict(cffi_resp.headers),
                url=str(cffi_resp.url),
                content=cffi_resp.content,
                text=cffi_resp.text,
                encoding=cffi_resp.encoding or "utf-8",
                elapsed=getattr(cffi_resp, "elapsed", 0.0),
                cookies=raw_cookies,
            )
        else:
            data_bytes = data.encode("utf-8") if isinstance(data, str) else data
            json_str = _json.dumps(json) if json is not None else None
            native_res = self._session.request(
                method=method,
                url=url,
                params=params,
                headers=req_headers,
                cookies=req_cookies,
                data=data_bytes,
                json=json_str,
                timeout=actual_timeout,
                _proxy=actual_proxy,
            )
            self.cookies.update(native_res.cookies)
            return Response(
                status_code=native_res.status_code,
                headers=native_res.headers,
                url=native_res.url,
                content=bytes(native_res.content),
                text=native_res.text,
                encoding=native_res.encoding,
                elapsed=native_res.elapsed,
                cookies=native_res.cookies,
            )

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
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:
        return self.request("OPTIONS", url, **kwargs)

    def __enter__(self) -> Session:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if hasattr(self._session, "close"):
            self._session.close()


class AsyncSession:
    """Asynchronous HTTP Session with requests and curl_cffi compatibility."""

    def __init__(
        self,
        impersonate: Union[str, BrowserType] = "chrome_152",
        timeout: float = 30.0,
        verify: bool = True,
        verify_ssl: bool = True,
        proxies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        allow_redirects: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        engine: str = "auto",
        **kwargs: Any,
    ) -> None:
        self._sync_session = Session(
            impersonate=impersonate,
            timeout=timeout,
            verify=verify,
            verify_ssl=verify_ssl,
            proxies=proxies,
            proxy=proxy,
            allow_redirects=allow_redirects,
            follow_redirects=follow_redirects,
            max_redirects=max_redirects,
            headers=headers,
            cookies=cookies,
            engine=engine,
            **kwargs,
        )

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

    async def __aenter__(self) -> AsyncSession:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._sync_session.__exit__(exc_type, exc_val, exc_tb)


def request(
    method: str,
    url: str,
    impersonate: Union[str, BrowserType] = "chrome_152",
    params: Optional[Dict[str, str]] = None,
    data: Optional[Union[bytes, str]] = None,
    json: Optional[Any] = None,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
    verify: bool = True,
    proxies: Optional[Dict[str, str]] = None,
    proxy: Optional[str] = None,
    allow_redirects: bool = True,
    auth: Optional[Tuple[str, str]] = None,
    engine: str = "auto",
    **kwargs: Any,
) -> Response:
    with Session(
        impersonate=impersonate,
        timeout=timeout or 30.0,
        verify=verify,
        proxies=proxies,
        proxy=proxy,
        allow_redirects=allow_redirects,
        auth=auth,
        engine=engine,
    ) as s:
        return s.request(
            method=method,
            url=url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            **kwargs,
        )


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
    return request("HEAD", url, impersonate=impersonate, **kwargs)


def options(url: str, impersonate: Union[str, BrowserType] = "chrome_152", **kwargs: Any) -> Response:
    return request("OPTIONS", url, impersonate=impersonate, **kwargs)
