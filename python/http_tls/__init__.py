"""http_tls: Standalone Rust + BoringSSL TLS & HTTP/2 Fingerprint Impersonating HTTP client for Python.

100% Drop-in replacement for `requests`, `httpx`, and `curl_cffi`:
    import http_tls as requests
    import http_tls as httpx
    from http_tls import requests, BrowserType
"""

from __future__ import annotations

import sys
from http_tls import auth, challenge, exceptions, requests, status_codes, structures
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
from http_tls.requests import (
    AsyncClient,
    AsyncSession,
    AsyncWebSocket,
    BrowserType,
    Client,
    Cookies,
    Response,
    Session,
    WebSocket,
    delete,
    gather,
    get,
    head,
    options,
    parse_ja3_to_tls_options,
    patch,
    post,
    put,
    request,
    supported_presets,
)
from http_tls.status_codes import codes
from http_tls.structures import CaseInsensitiveDict

try:
    from http_tls._core import __version__
except ImportError:
    __version__ = "0.6.0"

sys.modules["http_tls.requests"] = requests

__all__ = [
    "requests",
    "auth",
    "challenge",
    "codes",
    "exceptions",
    "structures",
    "CaseInsensitiveDict",
    "AuthBase",
    "BasicAuth",
    "BearerAuth",
    "DigestAuth",
    "RequestException",
    "HTTPError",
    "ConnectionError",
    "Timeout",
    "ConnectTimeout",
    "ReadTimeout",
    "SSLError",
    "TooManyRedirects",
    "Response",
    "Session",
    "AsyncSession",
    "Client",
    "AsyncClient",
    "WebSocket",
    "AsyncWebSocket",
    "Cookies",
    "BrowserType",
    "parse_ja3_to_tls_options",
    "gather",
    "request",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "options",
    "supported_presets",
    "__version__",
]
