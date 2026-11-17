"""Anti-bot interstitial detection.

Classifies a response as a JavaScript / browser-verification interstitial
served by a known edge provider. Pure inspection: nothing is executed.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

__all__ = ["detect", "CLEARANCE_COOKIES"]

# Cookie(s) each provider sets once the browser check has passed.
CLEARANCE_COOKIES: Dict[str, Tuple[str, ...]] = {
    "cloudflare": ("cf_clearance",),
    "ddos-guard": ("__ddg2_", "__ddgid_", "__ddg1_"),
    "datadome": ("datadome",),
    "perimeterx": ("_px3", "_pxvid"),
    "imperva": ("reese84", "incap_ses_"),
    "sucuri": ("sucuri_cloudproxy_uuid_",),
    "vercel": ("_vcrcs",),
    "akamai": ("_abck",),
}

_CHALLENGE_STATUSES = (403, 429, 503)


def _body(resp: Any, limit: int = 32768) -> str:
    # Never force-read a streamed body just to classify it.
    if getattr(resp, "_content", b"") is None:
        return ""
    try:
        return (resp.text or "")[:limit]
    except Exception:
        return ""


def detect(resp: Any) -> Optional[str]:
    """Return the provider name if `resp` is a browser-check interstitial, else None."""
    headers = resp.headers
    status = int(resp.status_code)
    server = str(headers.get("server", "")).lower()

    # Explicit signals first: these headers are only sent on challenge pages.
    if str(headers.get("cf-mitigated", "")).lower() == "challenge":
        return "cloudflare"
    if str(headers.get("x-vercel-mitigated", "")).lower() == "challenge":
        return "vercel"

    if status not in _CHALLENGE_STATUSES and status != 200:
        return None

    body = _body(resp)
    low = body.lower()

    if "cloudflare" in server and status in _CHALLENGE_STATUSES and (
        "challenge-platform" in low or "cf_chl_opt" in low or "<title>just a moment" in low
    ):
        return "cloudflare"

    if ("ddos-guard" in server or "ddg" in server) and status in _CHALLENGE_STATUSES:
        return "ddos-guard"
    if "check.ddos-guard.net" in low or "ddos-guard/js-challenge" in low:
        return "ddos-guard"

    if "x-datadome" in headers or "x-dd-b" in headers:
        if status in _CHALLENGE_STATUSES or "captcha-delivery.com" in low:
            return "datadome"

    if status in _CHALLENGE_STATUSES and ("px-captcha" in low or "_pxappid" in low):
        return "perimeterx"

    if "_incapsula_resource" in low or ("x-iinfo" in headers and status in _CHALLENGE_STATUSES):
        return "imperva"

    if "sucuri" in server and "sucuri_cloudproxy_js" in low:
        return "sucuri"

    if "akamaighost" in server and status == 403 and "reference&#32;&#35;" in low:
        return "akamai"

    return None
