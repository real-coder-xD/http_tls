"""Authentication handlers compatible with requests.auth and httpx.Auth."""

from __future__ import annotations

import base64
import hashlib
import os
import re
from typing import Dict, Optional
from urllib.parse import urlsplit

__all__ = ["AuthBase", "BasicAuth", "BearerAuth", "DigestAuth"]


class AuthBase:
    """Base authentication handler."""

    def apply(self, headers: Dict[str, str]) -> None:
        return None


class BasicAuth(AuthBase):
    """HTTP Basic Authentication."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        self._header = f"Basic {token}"

    def apply(self, headers: Dict[str, str]) -> None:
        headers["Authorization"] = self._header


class BearerAuth(AuthBase):
    """HTTP Bearer Token Authentication."""

    def __init__(self, token: str) -> None:
        self.token = token
        self._header = f"Bearer {token}"

    def apply(self, headers: Dict[str, str]) -> None:
        headers["Authorization"] = self._header


_DIGEST_KV_RE = re.compile(r'([a-zA-Z0-9_-]+)=(?:"([^"]*)"|([^\s,]*))')


class DigestAuth(AuthBase):
    """RFC 7616 / RFC 2617 HTTP Digest Authentication (MD5, MD5-sess, SHA-256, SHA-256-sess)."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self._nc = 0
        self._last_challenge: Optional[Dict[str, str]] = None

    @staticmethod
    def parse_challenge(www_authenticate: str) -> Optional[Dict[str, str]]:
        if not www_authenticate:
            return None
        # Handle multiple challenges in one header; locate Digest section
        idx = www_authenticate.lower().find("digest ")
        if idx == -1:
            return None
        params: Dict[str, str] = {}
        for m in _DIGEST_KV_RE.finditer(www_authenticate[idx + 7:]):
            k = m.group(1).lower()
            v = m.group(2) if m.group(2) is not None else m.group(3)
            params[k] = v
        return params if "realm" in params and "nonce" in params else None

    def build_header(self, method: str, url: str, challenge: Dict[str, str]) -> str:
        self._last_challenge = challenge
        self._nc += 1
        nc_hex = f"{self._nc:08x}"
        cnonce = os.urandom(8).hex()

        realm = challenge.get("realm", "")
        nonce = challenge.get("nonce", "")
        opaque = challenge.get("opaque")
        alg_raw = challenge.get("algorithm", "MD5").upper()
        qop_raw = challenge.get("qop", "")

        if alg_raw.startswith("SHA-256") or alg_raw.startswith("SHA256"):
            h = lambda s: hashlib.sha256(s.encode("utf-8")).hexdigest()
        elif alg_raw.startswith("SHA-512") or alg_raw.startswith("SHA512"):
            h = lambda s: hashlib.sha512(s.encode("utf-8")).hexdigest()
        else:
            h = lambda s: hashlib.md5(s.encode("utf-8")).hexdigest()

        parsed = urlsplit(url)
        uri = parsed.path or "/"
        if parsed.query:
            uri = f"{uri}?{parsed.query}"

        ha1 = h(f"{self.username}:{realm}:{self.password}")
        if alg_raw.endswith("-SESS"):
            ha1 = h(f"{ha1}:{nonce}:{cnonce}")

        ha2 = h(f"{method.upper()}:{uri}")

        qops = [q.strip().lower() for q in qop_raw.split(",") if q.strip()]
        if "auth" in qops:
            qop = "auth"
            response = h(f"{ha1}:{nonce}:{nc_hex}:{cnonce}:{qop}:{ha2}")
        elif not qops:
            qop = None
            response = h(f"{ha1}:{nonce}:{ha2}")
        else:
            qop = qops[0]
            response = h(f"{ha1}:{nonce}:{nc_hex}:{cnonce}:{qop}:{ha2}")

        parts = [
            f'username="{self.username}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{uri}"',
            f'response="{response}"',
        ]
        if alg_raw:
            parts.append(f"algorithm={alg_raw}")
        if qop:
            parts.append(f"qop={qop}")
            parts.append(f"nc={nc_hex}")
            parts.append(f'cnonce="{cnonce}"')
        if opaque is not None:
            parts.append(f'opaque="{opaque}"')

        return "Digest " + ", ".join(parts)
