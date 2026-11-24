"""Drop-in compatibility module matching requests, httpx, and curl_cffi APIs.

Provides `Session`, `AsyncSession`, `Client`, `AsyncClient`, and top-level helpers (`get`, `post`,
`request`, `stream`, `gather`), while re-exporting all data models (`Response`, `Cookies`,
`BrowserType`, `TimeoutConfig`, `Limits`, `MockTransport`, `WebSocket`, `AsyncWebSocket`,
`Element`, `HtmlDocument`, `JsonDocument`) from `http_tls.models` for 100% backwards compatibility.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, contextmanager
import datetime as _dt
import inspect
import json as _json
import os
import random as _random
import time as _time
from typing import Any, AsyncIterator, Callable, Dict, Iterator, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlencode, urljoin, urlparse

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
from http_tls.models import (
    BrowserType,
    Cookies,
    Element,
    HtmlDocument,
    JsonDocument,
    Limits,
    MockTransport,
    Response,
    STABLE_PRESETS,
    TimeoutConfig,
    WebSocket,
    AsyncWebSocket,
    __version__,
    _NativeWebSocket,
    _RustSession,
    _apply_fetch_headers,
    _build_history_responses,
    _coerce_auth,
    _extract_proxy,
    _native_chunks,
    _normalize_files,
    _OkDescriptor,
    _read_file,
    _rust_extract_between,
    _rust_extract_between_all,
    _rust_extract_json_path,
    _rust_extract_re,
    _rust_extract_re_first,
    _rust_is_verified_preset,
    _rust_parse_html,
    _rust_parse_json,
    _rust_presets,
    _split_identity,
    _split_verify,
    _translate_error,
    _try_extract_inline_cookie,
    _unpack_timeout,
    is_verified_preset,
    parse_akamai_h2_to_http2_options,
    parse_ja3_to_tls_options,
    supported_presets,
    _CffiSession,
    _HAS_CFFI,
)
from http_tls.solvers import infer_impersonate_from_user_agent, run_coroutine_sync
from http_tls.status_codes import codes
from http_tls.structures import CaseInsensitiveDict

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
        http3: bool = False,
        http3_only: bool = False,
        auto_upgrade_h3: bool = True,
        ech: bool = False,
        ech_doh_url: str = "https://cloudflare-dns.com/dns-query",
        doh: bool = False,
        doh_url: Optional[str] = None,
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
        self.retries = max(0, retries)
        self.retry_backoff = float(retry_backoff)
        self.retry_statuses = tuple(retry_statuses)
        self.retry_on_challenge = retry_on_challenge
        self.rotate_impersonate = rotate_impersonate
        self.keylog_file = keylog_file
        self.system_dns = system_dns
        self.record_har = record_har
        self.har_entries: List[Dict[str, Any]] = []
        self.flare_solverr_url = flare_solverr_url
        self.solver = solver
        self.auto_referer = auto_referer
        self.fetch_mode = fetch_mode
        self.transport = transport
        self._last_url: Optional[str] = None
        self.http3 = http3 or http3_only or (ech and not http1_only and not http2_only)
        self.http3_only = http3_only
        self.ech = ech
        self.ech_doh_url = ech_doh_url
        self.doh_url: Optional[str] = doh_url or ("https://cloudflare-dns.com/dns-query" if doh else None)
        self.auto_upgrade_h3 = (
            auto_upgrade_h3
            and not http1_only
            and not http2_only
            and not akamai_h2
            and not http2_options
            and not ja3
            and not tls_options
        )
        self.alt_svc_cache: Dict[str, Dict[str, str]] = {}
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
        self._session: Any = None
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
            if not _HAS_CFFI or _CffiSession is None:
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
                http3=self.http3,
                http3_only=self.http3_only,
                ech=self.ech,
                ech_doh_url=self.ech_doh_url,
                doh_url=self.doh_url,
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

    def _lookup_alt_svc_h3(self, url: str) -> Tuple[bool, Optional[int]]:
        if not self.alt_svc_cache or not url.startswith("https://"):
            return False, None
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False, None
        alt = self.alt_svc_cache.get(host)
        if not alt:
            return False, None
        authority = alt.get("h3") or alt.get("h3-29")
        if not authority:
            return False, None
        if ":" in authority:
            port_s = authority.rsplit(":", 1)[-1].strip()
            if port_s.isdigit():
                return True, int(port_s)
        return True, 443

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
                http3=spec.get("http3"),
                ech=spec.get("ech"),
                ech_config_list=spec.get("ech_config_list"),
            )
            native_specs.append(args)
            meta_list.append((method, full_url, args.get("headers")))

        try:
            natives = self._session.gather(native_specs, concurrency=max(1, concurrency))
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
        http3: Optional[bool] = None,
        ech: Optional[bool] = None,
        ech_config_list: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        req_headers = dict(self.headers.items())
        if headers:
            req_headers.update(headers)

        merged_params: Optional[Dict[str, str]] = None
        if self.params or params:
            mp: Dict[Any, Any] = dict(self.params)
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
                    mp_files.append((k, None, str(v).encode("utf-8"), None))
        elif isinstance(data, dict):
            body = urlencode(data, doseq=True).encode("utf-8")
            if not any(k.lower() == "content-type" for k in req_headers):
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif isinstance(data, str):
            body = data.encode("utf-8")
        elif data is not None:
            body = data

        verify_flag: Optional[bool] = None
        ca_bytes: Optional[bytes] = None
        if verify is not None:
            v_bool, ca_path = _split_verify(verify)
            verify_flag = v_bool
            if ca_path:
                ca_bytes = _read_file(ca_path)

        has_alt_h3, alt_port = self._lookup_alt_svc_h3(url)
        eff_http3: Optional[bool] = http3
        proxy_supports_h3 = not actual_proxy or actual_proxy.lower().startswith(("socks5://", "socks5h://"))
        if eff_http3 is None and self.auto_upgrade_h3 and has_alt_h3 and proxy_supports_h3:
            eff_http3 = True

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
            impersonate=impersonate_override if impersonate_override else None,
            local_address=local_address,
            http3=eff_http3,
            alt_svc_port=alt_port,
            ech=ech,
            ech_config_list=ech_config_list,
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
            ech_accepted=bool(getattr(native, "ech_accepted", False)),
            tls_resumed=bool(getattr(native, "tls_resumed", False)),
        )
        if stream:
            out_resp = Response(
                content=None,
                encoding=native.encoding or "utf-8",
                raw_chunks=None if is_async else _native_chunks(native),
                async_stream=native if is_async else None,
                closer=native.close,
                **common,
            )
        else:
            out_resp = Response(content=native.content, text=native.text, encoding=native.encoding, **common)
        for h_resp in (*hist, out_resp):
            if "alt-svc" in h_resp.headers:
                host = (urlparse(h_resp.url).hostname or "").lower()
                if host:
                    parsed_alt = h_resp.alt_svc
                    if parsed_alt:
                        self.alt_svc_cache[host] = parsed_alt
                    else:
                        self.alt_svc_cache.pop(host, None)
        return out_resp

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
        http3: Optional[bool] = None,
        ech: Optional[bool] = None,
        ech_config_list: Optional[bytes] = None,
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
        sticky_proxy: Optional[str] = None
        solved_clearance = False

        for attempt in range(max_attempts):
            attempt_proxy = proxy or sticky_proxy or (self._next_pool_proxy() if not proxies else None)
            attempt_imp = str(impersonate) if impersonate else (
                "weighted_random"
                if (attempt > 0 and not solved_clearance and (self.rotate_impersonate or self.retry_on_challenge))
                else None
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
                        header_order, attempt_imp, local_address, http3, ech, ech_config_list,
                    )
                    call = self._session.request_stream if stream else self._session.request
                    resp = self._wrap_native(call(**args), stream=stream, is_async=False)

                resp.proxy = attempt_proxy or _extract_proxy(None, proxies) or _extract_proxy(None, self.proxies)

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
                            header_order, attempt_imp, local_address, http3, ech, ech_config_list,
                        )
                        call = self._session.request_stream if stream else self._session.request
                        resp = self._wrap_native(call(**args), stream=stream, is_async=False)
                        resp.proxy = attempt_proxy or _extract_proxy(None, proxies) or _extract_proxy(None, self.proxies)

                if attempt + 1 < max_attempts and self._should_retry_resp(resp):
                    if resp.challenge is not None or _try_extract_inline_cookie(resp.text):
                        try:
                            if self.solve_challenge(resp):
                                solved_clearance = True
                                sticky_proxy = resp.proxy
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
        alt = resp.alt_svc
        if alt:
            host = (urlparse(self._last_url).hostname or "").lower()
            if host:
                self.alt_svc_cache[host] = alt
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
            mp: Dict[Any, Any] = dict(self.params)
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
    def stream(self, method: str, url: str, **kwargs: Any):
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
        http3: Optional[bool] = None,
        ech: Optional[bool] = None,
        ech_config_list: Optional[bytes] = None,
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
        sticky_proxy: Optional[str] = None
        solved_clearance = False

        for attempt in range(max_attempts):
            attempt_proxy = proxy or sticky_proxy or (s._next_pool_proxy() if not proxies else None)
            attempt_imp = str(impersonate) if impersonate else (
                "weighted_random"
                if (attempt > 0 and not solved_clearance and (s.rotate_impersonate or s.retry_on_challenge))
                else None
            )
            try:
                args = s._build_native_args(
                    method, full_url, params, req_headers, cookies, data, json, files,
                    timeout, verify, proxies, attempt_proxy, allow_redirects, auth_obj,
                    header_order, attempt_imp, local_address, http3, ech, ech_config_list,
                )
                call = s._session.async_request_stream if stream else s._session.async_request
                resp = s._wrap_native(await call(**args), stream=stream, is_async=True)
                resp.proxy = attempt_proxy or _extract_proxy(None, proxies) or _extract_proxy(None, s.proxies)

                if isinstance(auth_obj, DigestAuth) and resp.status_code == 401:
                    www = resp.headers.get("www-authenticate", "")
                    chal = auth_obj.parse_challenge(www)
                    if chal is not None:
                        digest_hdrs = dict(req_headers)
                        digest_hdrs["Authorization"] = auth_obj.build_header(method, resp.url, chal)
                        args = s._build_native_args(
                            method, full_url, params, digest_hdrs, cookies, data, json, files,
                            timeout, verify, proxies, attempt_proxy, allow_redirects, None,
                            header_order, attempt_imp, local_address, http3, ech, ech_config_list,
                        )
                        call = s._session.async_request_stream if stream else s._session.async_request
                        resp = s._wrap_native(await call(**args), stream=stream, is_async=True)
                        resp.proxy = attempt_proxy or _extract_proxy(None, proxies) or _extract_proxy(None, s.proxies)

                if attempt + 1 < max_attempts and s._should_retry_resp(resp):
                    if resp.challenge is not None or _try_extract_inline_cookie(resp.text):
                        try:
                            if await self.solve_challenge(resp):
                                solved_clearance = True
                                sticky_proxy = resp.proxy
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
        alt = resp.alt_svc
        if alt:
            host = (urlparse(s._last_url).hostname or "").lower()
            if host:
                s.alt_svc_cache[host] = alt
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
    async def stream(self, method: str, url: str, **kwargs: Any):
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
    "http2_options", "akamai_h2", "http1_only", "http2_only", "http3", "http3_only", "auto_upgrade_h3",
    "ech", "ech_doh_url", "doh", "doh_url", "resolve", "local_address", "interface",
    "tls_info", "keylog_file", "system_dns", "limits", "tcp_nodelay", "tcp_keepalive",
    "auto_referer", "fetch_mode", "transport", "retries", "retry_backoff", "retry_statuses",
    "retry_on_challenge", "rotate_impersonate", "event_hooks", "engine",
)
_REQ_SKIP_KEYS = {
    "engine", "cert", "tls_options", "ja3", "http2_options", "akamai_h2", "http1_only", "http2_only",
    "http3_only", "auto_upgrade_h3", "ech_doh_url", "doh", "doh_url",
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
):
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
