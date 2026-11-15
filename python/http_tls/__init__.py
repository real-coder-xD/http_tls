"""http_tls: High-performance Rust & TLS Fingerprint Impersonating HTTP client for Python.

100% Drop-in replacement for both `requests` and `curl_cffi.requests`:
    import http_tls as requests
    from http_tls import requests
"""

from __future__ import annotations

import sys
from http_tls import exceptions, requests, status_codes, structures
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
    AsyncSession,
    BrowserType,
    Response,
    Session,
    delete,
    get,
    head,
    options,
    patch,
    post,
    put,
    request,
    supported_presets,
)
from http_tls.status_codes import codes
from http_tls.structures import CaseInsensitiveDict

# Package version
try:
    from http_tls._core import __version__
except ImportError:
    __version__ = "0.2.0"

# Register module alias in sys.modules so `import http_tls.requests as requests` works
sys.modules["http_tls.requests"] = requests

__all__ = [
    # Requests compatibility
    "requests",
    "codes",
    "exceptions",
    "structures",
    "CaseInsensitiveDict",
    "RequestException",
    "HTTPError",
    "ConnectionError",
    "Timeout",
    "ConnectTimeout",
    "ReadTimeout",
    "SSLError",
    "TooManyRedirects",
    # Main classes & funcs
    "Response",
    "Session",
    "AsyncSession",
    "BrowserType",
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
