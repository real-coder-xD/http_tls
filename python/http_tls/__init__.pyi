from enum import Enum
from typing import Any, AsyncContextManager, AsyncIterator, Callable, ContextManager, Dict, Iterator, List, Optional, Sequence, Tuple, Union
from http_tls import auth, challenge, exceptions, status_codes, structures
from http_tls.auth import AuthBase, BasicAuth, BearerAuth, DigestAuth
from http_tls.exceptions import (
    ConnectError,
    ConnectTimeout,
    ConnectionError,
    HTTPError,
    HTTPStatusError,
    InvalidURL,
    ReadTimeout,
    RequestError,
    RequestException,
    RequestsError,
    SSLError,
    Timeout,
    TimeoutException,
    TooManyRedirects,
)
from http_tls.status_codes import codes
from http_tls.structures import CaseInsensitiveDict

__version__: str
requests: Any
solvers: Any
STABLE_PRESETS: Tuple[str, ...]

def infer_impersonate_from_user_agent(ua: str) -> Optional[str]: ...
def run_coroutine_sync(coro: Any, timeout: Optional[float] = None) -> Dict[str, Any]: ...

class BrowserType(str, Enum):
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

class BestDriverSolver:
    headless: bool
    timeout: float
    proxy: Optional[str]
    wait_cookies: Tuple[str, ...]
    browser_path: Optional[str]
    extra_args: Optional[List[str]]
    keep_warm: bool
    max_warm_browsers: int
    cache_ttl: float
    click_turnstile: bool
    def __init__(
        self,
        headless: bool = True,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        wait_cookies: Sequence[str] = ...,
        browser_path: Optional[str] = None,
        extra_args: Optional[Sequence[str]] = None,
        keep_warm: bool = False,
        max_warm_browsers: int = 4,
        cache_ttl: float = 15.0,
        click_turnstile: bool = True,
    ) -> None: ...
    async def asolve(self, url: str, resp: Any = None) -> Dict[str, Any]: ...
    def __call__(self, url: str, resp: Any = None) -> Dict[str, Any]: ...
    async def aclose(self) -> None: ...
    def close(self) -> None: ...
    def __enter__(self) -> "BestDriverSolver": ...
    def __exit__(self, *exc: Any) -> None: ...
    async def __aenter__(self) -> "BestDriverSolver": ...
    async def __aexit__(self, *exc: Any) -> None: ...

class PlaywrightSolver:
    headless: bool
    timeout: float
    proxy: Optional[str]
    wait_cookies: Tuple[str, ...]
    browser_type: str
    keep_warm: bool
    cache_ttl: float
    click_turnstile: bool
    def __init__(
        self,
        headless: bool = True,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        wait_cookies: Sequence[str] = ...,
        browser_type: str = "chromium",
        keep_warm: bool = False,
        cache_ttl: float = 15.0,
        click_turnstile: bool = True,
    ) -> None: ...
    def __call__(self, url: str, resp: Any = None) -> Dict[str, Any]: ...
    def close(self) -> None: ...
    async def aclose(self) -> None: ...
    def __enter__(self) -> "PlaywrightSolver": ...
    def __exit__(self, *exc: Any) -> None: ...
    async def __aenter__(self) -> "PlaywrightSolver": ...
    async def __aexit__(self, *exc: Any) -> None: ...

class FlareSolverrSolver:
    endpoint: str
    max_timeout_ms: int
    proxy: Optional[str]
    cache_ttl: float
    def __init__(
        self,
        endpoint: str = "http://localhost:8191/v1",
        max_timeout_ms: int = 60000,
        proxy: Optional[str] = None,
        cache_ttl: float = 15.0,
    ) -> None: ...
    def __call__(self, url: str, resp: Any = None) -> Dict[str, Any]: ...

def supported_presets() -> List[str]: ...
def is_verified_preset(preset: str) -> bool: ...
def parse_ja3_to_tls_options(ja3: str) -> Dict[str, Any]: ...
def parse_akamai_h2_to_http2_options(akamai_fp: str) -> Dict[str, Any]: ...

class TimeoutConfig:
    timeout: Optional[float]
    connect: Optional[float]
    read: Optional[float]
    write: Optional[float]
    pool: Optional[float]
    def __init__(
        self,
        timeout: Optional[float] = 30.0,
        *,
        connect: Optional[float] = None,
        read: Optional[float] = None,
        write: Optional[float] = None,
        pool: Optional[float] = None,
    ) -> None: ...
    def total(self) -> float: ...

class Limits:
    max_connections: Optional[int]
    max_keepalive_connections: Optional[int]
    keepalive_expiry: Optional[float]
    def __init__(
        self,
        max_connections: Optional[int] = None,
        max_keepalive_connections: Optional[int] = None,
        keepalive_expiry: Optional[float] = 5.0,
    ) -> None: ...

class MockTransport:
    handler: Callable[[Dict[str, Any]], Any]
    def __init__(self, handler: Callable[[Dict[str, Any]], Any]) -> None: ...
    def handle_request(self, request_ctx: Dict[str, Any]) -> "Response": ...
    async def handle_async_request(self, request_ctx: Dict[str, Any]) -> "Response": ...

class Cookies(dict):
    def __init__(
        self,
        initial: Optional[Dict[str, str]] = None,
        on_clear: Optional[Callable[[], None]] = None,
        on_set: Optional[Callable[[str, str, Optional[str], Optional[str], bool, bool], None]] = None,
        on_delete: Optional[Callable[[str, Optional[str], Optional[str]], None]] = None,
    ) -> None: ...
    def clear(self) -> None: ...
    def set(
        self,
        name: str,
        value: str,
        domain: Optional[str] = None,
        path: Optional[str] = None,
        secure: bool = False,
        http_only: bool = False,
    ) -> None: ...
    def get(
        self,
        name: str,
        default: Any = None,
        domain: Optional[str] = None,
        path: Optional[str] = None,
    ) -> Any: ...
    def delete(self, name: str, domain: Optional[str] = None, path: Optional[str] = None) -> None: ...
    def list_records(self) -> List[Dict[str, Any]]: ...
    def get_dict(self, domain: Optional[str] = None, path: Optional[str] = None) -> Dict[str, str]: ...

class Element:
    """Native Rust HTML5 DOM element supporting chained CSS3, XPath 1.0, regex, DOM navigation, and dict-like attribute access."""
    tag: str
    text: str
    own_text: str
    html: str
    outer_html: str
    attrs: Dict[str, str]
    attrib: Dict[str, str]
    parent: Optional["Element"]
    children: List["Element"]
    next_sibling: Optional["Element"]
    prev_sibling: Optional["Element"]
    ancestors: List["Element"]
    def get_text(self, separator: str = " ", strip: bool = True) -> str:
        """BeautifulSoup-compatible text join across descendant text nodes with `separator`."""
        ...
    def attr(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Return attribute `name` or `default` if absent."""
        ...
    def css(self, selector: str) -> List[Any]:
        """Query descendants with Rust CSS3 (`:has()`, `:contains()`, `::text`, `::attr(name)`)."""
        ...
    def css_first(self, selector: str, default: Any = None) -> Optional[Any]:
        """Return the first matching descendant via Rust CSS3 (or `default`)."""
        ...
    def select(self, selector: str) -> List[Any]:
        """BeautifulSoup-compatible alias for `css(selector)`."""
        ...
    def select_one(self, selector: str, default: Any = None) -> Optional[Any]:
        """BeautifulSoup-compatible alias for `css_first(selector, default=default)`."""
        ...
    def xpath(self, expr: str) -> List[Any]:
        """Query relative to this element using the native Rust XPath 1.0 evaluator."""
        ...
    def xpath_first(self, expr: str, default: Any = None) -> Optional[Any]:
        """Return the first XPath 1.0 match relative to this element (or `default`)."""
        ...
    def find(self, query: str, default: Any = None) -> Optional[Any]:
        """Auto-dispatch first match: XPath (`/...`, `.//...`, XPath axes) or CSS3 (incl. `::text`/`::attr()`)."""
        ...
    def find_all(self, query: str) -> List[Any]:
        """Auto-dispatch all matches: XPath (`/...`, `.//...`, XPath axes) or CSS3 (incl. `::text`/`::attr()`)."""
        ...
    def re(self, pattern: str) -> List[str]:
        """Extract all Rust linear-time DFA regex matches from `self.text`."""
        ...
    def re_first(self, pattern: str, default: Optional[str] = None) -> Optional[str]:
        """Extract the first Rust linear-time DFA regex match from `self.text` (or `default`)."""
        ...
    def between(self, left: str, right: str, default: Optional[str] = None) -> Optional[str]:
        """Extract the first substring between `left` and `right` delimiters from `self.text` (or `default`)."""
        ...
    def between_all(self, left: str, right: str) -> List[str]:
        """Extract all substrings between `left` and `right` delimiters from `self.text`."""
        ...
    def __getitem__(self, key: str) -> str: ...
    def __contains__(self, key: str) -> bool: ...

class HtmlDocument:
    """Standalone thread-safe Rust WHATWG HTML5 DOM document."""
    text: str
    html: str
    def __init__(self, html: str) -> None: ...
    def get_text(self, separator: str = " ", strip: bool = True) -> str:
        """BeautifulSoup-compatible text join across all HTML text nodes with `separator`."""
        ...
    def css(self, selector: str) -> List[Any]:
        """Query document with Rust CSS3 (`:has()`, `:contains()`, `::text`, `::attr(name)`)."""
        ...
    def css_first(self, selector: str, default: Any = None) -> Optional[Any]:
        """Return the first Rust CSS3 match (or `default`)."""
        ...
    def select(self, selector: str) -> List[Any]:
        """BeautifulSoup-compatible alias for `css(selector)`."""
        ...
    def select_one(self, selector: str, default: Any = None) -> Optional[Any]:
        """BeautifulSoup-compatible alias for `css_first(selector, default=default)`."""
        ...
    def xpath(self, expr: str) -> List[Any]:
        """Query document with the native Rust XPath 1.0 evaluator."""
        ...
    def xpath_first(self, expr: str, default: Any = None) -> Optional[Any]:
        """Return the first native Rust XPath 1.0 match (or `default`)."""
        ...
    def find(self, query: str, default: Any = None) -> Optional[Any]:
        """Auto-dispatch first match: XPath (`/...`, `.//...`, XPath axes) or CSS3 (incl. `::text`/`::attr()`)."""
        ...
    def find_all(self, query: str) -> List[Any]:
        """Auto-dispatch all matches: XPath (`/...`, `.//...`, XPath axes) or CSS3 (incl. `::text`/`::attr()`)."""
        ...

class Response:
    status_code: int
    headers: CaseInsensitiveDict
    url: str
    content: bytes
    text: str
    encoding: Optional[str]
    elapsed: float
    cookies: Cookies
    http_version: str
    remote_addr: Optional[str]
    peer_certificate: Optional[bytes]
    history: List["Response"]
    proxy: Optional[str]
    ech_accepted: bool
    tls_resumed: bool

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
    ) -> None: ...

    @property
    def ok(self) -> bool: ...
    @property
    def is_success(self) -> bool: ...
    @property
    def is_informational(self) -> bool: ...
    @property
    def is_redirect(self) -> bool: ...
    @property
    def is_permanent_redirect(self) -> bool: ...
    @property
    def has_redirect_location(self) -> bool: ...
    @property
    def num_bytes_downloaded(self) -> int: ...
    @property
    def is_client_error(self) -> bool: ...
    @property
    def is_server_error(self) -> bool: ...
    @property
    def is_error(self) -> bool: ...
    @property
    def reason(self) -> str: ...
    @property
    def reason_phrase(self) -> str: ...
    @property
    def links(self) -> Dict[str, Dict[str, str]]: ...
    @property
    def challenge(self) -> Optional[str]: ...
    @property
    def alt_svc(self) -> Dict[str, str]: ...

    def read(self) -> bytes: ...
    async def aread(self) -> bytes: ...
    async def acontent(self) -> bytes: ...
    async def atext(self) -> str: ...
    def json(self, **kwargs: Any) -> Any: ...
    @property
    def html_doc(self) -> HtmlDocument:
        """Lazily parsed thread-safe Rust WHATWG HTML5 `HtmlDocument` cached on this response."""
        ...
    def css(self, selector: str) -> List[Any]:
        """Query HTML with Rust CSS3 selectors (`:has()`, `:contains()`, `:has-text()`, `::text`, `::attr(name)`)."""
        ...
    def css_first(self, selector: str, default: Any = None) -> Optional[Any]:
        """Return the first Rust CSS3 selector match (or `default`)."""
        ...
    def select(self, selector: str) -> List[Any]:
        """BeautifulSoup-compatible alias for `css(selector)`."""
        ...
    def select_one(self, selector: str, default: Any = None) -> Optional[Any]:
        """BeautifulSoup-compatible alias for `css_first(selector, default=default)`."""
        ...
    def xpath(self, expr: str) -> List[Any]:
        """Query HTML with the native Rust XPath 1.0 evaluator (axes, predicates, `text()`, `@attr`, `|`)."""
        ...
    def xpath_first(self, expr: str, default: Any = None) -> Optional[Any]:
        """Return the first native Rust XPath 1.0 match (or `default`)."""
        ...
    def find(self, query: str, default: Any = None) -> Optional[Any]:
        """Auto-dispatch first match: JSON path (`$.`, `$..`, `$[`), XPath (`/...`, `.//...`, XPath axes), or CSS3 (incl. `::text`/`::attr()`)."""
        ...
    def find_all(self, query: str) -> List[Any]:
        """Auto-dispatch all matches: JSON path (`$.`, `$..`, `$[`), XPath (`/...`, `.//...`, XPath axes), or CSS3 (incl. `::text`/`::attr()`)."""
        ...
    def get_text(self, separator: str = " ", strip: bool = True) -> str:
        """BeautifulSoup-compatible text join across all HTML text nodes with `separator`."""
        ...
    def urljoin(self, url: str) -> str:
        """Scrapy-compatible absolute URL resolver relative to `self.url`."""
        ...
    def re(self, pattern: str) -> List[str]:
        """Extract all matches from `self.text` using Rust's linear-time DFA regex engine (ReDoS-safe)."""
        ...
    def re_first(self, pattern: str, default: Optional[str] = None) -> Optional[str]:
        """Return the first match from `self.text` (or `default`) using Rust's linear-time DFA regex engine."""
        ...
    def between(self, left: str, right: str, default: Optional[str] = None) -> Optional[str]:
        """Extract the first substring between `left` and `right` delimiters from `self.text` in Rust (or `default`)."""
        ...
    def between_all(self, left: str, right: str) -> List[str]:
        """Extract all substrings between `left` and `right` delimiters from `self.text` in Rust."""
        ...
    def json_path(self, path: str, default: Any = None) -> Any:
        """Extract a nested value from JSON in Rust (`a.b[0].c`, `items[-1].id`, `items[0:5]`, `items[*].name`, `$..price`)."""
        ...
    def raise_for_status(self) -> None: ...
    def iter_content(self, chunk_size: Optional[int] = 1, decode_unicode: bool = False) -> Iterator[Any]: ...
    def iter_bytes(self, chunk_size: Optional[int] = None) -> Iterator[bytes]: ...
    def iter_text(self, chunk_size: Optional[int] = None) -> Iterator[str]: ...
    def iter_lines(self, chunk_size: int = 512, decode_unicode: bool = False, delimiter: Optional[Any] = None) -> Iterator[Any]: ...
    def aiter_bytes(self, chunk_size: Optional[int] = None) -> AsyncIterator[bytes]: ...
    def aiter_content(self, chunk_size: Optional[int] = None) -> AsyncIterator[bytes]: ...
    def aiter_text(self, chunk_size: Optional[int] = None) -> AsyncIterator[str]: ...
    def aiter_lines(self) -> AsyncIterator[str]: ...
    def close(self) -> None: ...
    async def aclose(self) -> None: ...
    def __enter__(self) -> "Response": ...
    def __exit__(self, *exc: Any) -> None: ...
    async def __aenter__(self) -> "Response": ...
    async def __aexit__(self, *exc: Any) -> None: ...

class WebSocket:
    status_code: int
    headers: CaseInsensitiveDict
    protocol: Optional[str]
    def send_text(self, text: str) -> None: ...
    def send_bytes(self, data: bytes) -> None: ...
    def send_json(self, obj: Any) -> None: ...
    def recv(self) -> Optional[Tuple[str, bytes]]: ...
    def recv_text(self) -> Optional[str]: ...
    def recv_json(self) -> Any: ...
    def close(self, code: int = 1000, reason: str = "") -> None: ...
    def __enter__(self) -> "WebSocket": ...
    def __exit__(self, *exc: Any) -> None: ...

class AsyncWebSocket:
    status_code: int
    headers: CaseInsensitiveDict
    protocol: Optional[str]
    async def send_text(self, text: str) -> None: ...
    async def send_bytes(self, data: bytes) -> None: ...
    async def send_json(self, obj: Any) -> None: ...
    async def recv(self) -> Optional[Tuple[str, bytes]]: ...
    async def recv_text(self) -> Optional[str]: ...
    async def recv_json(self) -> Any: ...
    async def close(self, code: int = 1000, reason: str = "") -> None: ...
    async def __aenter__(self) -> "AsyncWebSocket": ...
    async def __aexit__(self, *exc: Any) -> None: ...

class Session:
    impersonate: str
    timeout: float
    base_url: str
    headers: CaseInsensitiveDict
    params: Dict[str, Any]
    cookies: Cookies
    proxies: Dict[str, str]
    proxies_pool: List[str]
    http3: bool
    http3_only: bool
    auto_upgrade_h3: bool
    ech: bool
    ech_doh_url: str
    doh_url: Optional[str]
    alt_svc_cache: Dict[str, Dict[str, str]]
    har_entries: List[Dict[str, Any]]
    event_hooks: Dict[str, List[Callable[..., Any]]]
    mode: str
    _session: Any

    def __init__(
        self,
        impersonate: str = "chrome_149",
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
    ) -> None: ...
    def clear_cookies(self) -> None: ...
    def set_impersonate(self, preset: Union[str, BrowserType]) -> None: ...
    def load_storage_state(self, state: Union[str, Dict[str, Any]], sync_impersonate: bool = True) -> Dict[str, Any]: ...
    def save_storage_state(self, path: Optional[str] = None) -> Dict[str, Any]: ...
    def export_har(self, path: Optional[str] = None) -> Dict[str, Any]: ...
    def clear_har(self) -> None: ...
    def solve_challenge(self, url_or_resp: Union[str, Response]) -> bool: ...
    def gather(self, urls_or_specs: Sequence[Union[str, Dict[str, Any]]], concurrency: int = 50, **common_kwargs: Any) -> List[Response]: ...
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
        impersonate: Optional[str] = None,
        local_address: Optional[str] = None,
        fetch_mode: Optional[str] = None,
        http3: Optional[bool] = None,
        ech: Optional[bool] = None,
        ech_config_list: Optional[bytes] = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Response: ...
    def ws_connect(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        proxies: Optional[Dict[str, str]] = None,
        verify: Optional[bool] = None,
    ) -> WebSocket: ...
    def get(self, url: str, **kwargs: Any) -> Response: ...
    def post(self, url: str, **kwargs: Any) -> Response: ...
    def put(self, url: str, **kwargs: Any) -> Response: ...
    def delete(self, url: str, **kwargs: Any) -> Response: ...
    def patch(self, url: str, **kwargs: Any) -> Response: ...
    def head(self, url: str, **kwargs: Any) -> Response: ...
    def options(self, url: str, **kwargs: Any) -> Response: ...
    def stream(self, method: str, url: str, **kwargs: Any) -> ContextManager[Response]: ...
    @property
    def is_closed(self) -> bool: ...
    def close(self) -> None: ...
    def __enter__(self) -> "Session": ...
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None: ...

class AsyncSession:
    impersonate: str
    headers: CaseInsensitiveDict
    cookies: Cookies
    params: Dict[str, Any]
    mode: str
    _sync_session: Session

    def __init__(
        self,
        impersonate: str = "chrome_149",
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
    ) -> None: ...
    @property
    def is_closed(self) -> bool: ...
    def clear_cookies(self) -> None: ...
    def set_impersonate(self, preset: Union[str, BrowserType]) -> None: ...
    def load_storage_state(self, state: Union[str, Dict[str, Any]], sync_impersonate: bool = True) -> Dict[str, Any]: ...
    def save_storage_state(self, path: Optional[str] = None) -> Dict[str, Any]: ...
    def export_har(self, path: Optional[str] = None) -> Dict[str, Any]: ...
    def clear_har(self) -> None: ...
    async def solve_challenge(self, url_or_resp: Union[str, Response]) -> bool: ...
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
        impersonate: Optional[str] = None,
        local_address: Optional[str] = None,
        fetch_mode: Optional[str] = None,
        http3: Optional[bool] = None,
        ech: Optional[bool] = None,
        ech_config_list: Optional[bytes] = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Response: ...
    def stream(self, method: str, url: str, **kwargs: Any) -> AsyncContextManager[Response]: ...
    async def ws_connect(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        proxies: Optional[Dict[str, str]] = None,
        verify: Optional[bool] = None,
    ) -> AsyncWebSocket: ...
    async def get(self, url: str, **kwargs: Any) -> Response: ...
    async def post(self, url: str, **kwargs: Any) -> Response: ...
    async def put(self, url: str, **kwargs: Any) -> Response: ...
    async def delete(self, url: str, **kwargs: Any) -> Response: ...
    async def patch(self, url: str, **kwargs: Any) -> Response: ...
    async def head(self, url: str, **kwargs: Any) -> Response: ...
    async def options(self, url: str, **kwargs: Any) -> Response: ...
    async def aclose(self) -> None: ...
    async def close(self) -> None: ...
    async def __aenter__(self) -> "AsyncSession": ...
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None: ...

Client = Session
AsyncClient = AsyncSession

def request(method: str, url: str, impersonate: str = "chrome_149", **kwargs: Any) -> Response: ...
def get(url: str, impersonate: str = "chrome_149", **kwargs: Any) -> Response: ...
def post(url: str, impersonate: str = "chrome_149", **kwargs: Any) -> Response: ...
def put(url: str, impersonate: str = "chrome_149", **kwargs: Any) -> Response: ...
def delete(url: str, impersonate: str = "chrome_149", **kwargs: Any) -> Response: ...
def patch(url: str, impersonate: str = "chrome_149", **kwargs: Any) -> Response: ...
def head(url: str, impersonate: str = "chrome_149", **kwargs: Any) -> Response: ...
def options(url: str, impersonate: str = "chrome_149", **kwargs: Any) -> Response: ...
def stream(method: str, url: str, impersonate: str = "chrome_149", **kwargs: Any) -> ContextManager[Response]: ...
def session(**kwargs: Any) -> Session: ...
def gather(urls_or_specs: Sequence[Union[str, Dict[str, Any]]], concurrency: int = 50, impersonate: str = "chrome_149", **kwargs: Any) -> List[Response]: ...
