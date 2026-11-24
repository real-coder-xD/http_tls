# Language: Python 3.8+ | File: python/http_tls/cli.py | Target: Built-in CLI Debugger (`http-tls` / `python -m http_tls`)
"""Zero-dependency CLI tool for testing TLS/JA4/HTTP3/ECH/DoH fingerprints and Rust CSS/XPath/JSON selectors."""

from __future__ import annotations

import argparse
import json as _json
import sys
from typing import Any, Dict, List, Optional, Sequence

import http_tls


def _parse_headers(raw_headers: Sequence[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in raw_headers:
        if ":" not in item:
            raise ValueError(f"Invalid header '{item}': expected 'Name: Value'")
        k, _, v = item.partition(":")
        out[k.strip()] = v.strip()
    return out


def _format_value(val: Any) -> str:
    if isinstance(val, (dict, list)):
        return _json.dumps(val, ensure_ascii=False, indent=2)
    return str(val)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="http-tls",
        description=(
            "Rust + Pure BoringSSL HTTP/1.1, HTTP/2 & HTTP/3 (Real ECH, DoH, SOCKS5 UDP) "
            "client & HTML5 CSS3/XPath/JSON extraction CLI."
        ),
    )
    p.add_argument("url", nargs="?", help="Target URL (https://...)")
    p.add_argument("-X", "--method", default="GET", help="HTTP method (default: GET)")
    p.add_argument("-i", "--impersonate", default="chrome_149", help="Browser preset (default: chrome_149)")
    p.add_argument("--http3", action="store_true", help="Enable Pure BoringSSL UDP QUIC HTTP/3")
    p.add_argument("--http3-only", action="store_true", help="Force HTTP/3 with no TCP fallback")
    p.add_argument("--ech", action="store_true", help="Enable Real ECH (Encrypted Client Hello -> sni=encrypted)")
    p.add_argument("--doh", action="store_true", help="Enable Session-wide DNS-over-HTTPS")
    p.add_argument("--doh-url", default=None, help="Custom DoH endpoint URL")
    p.add_argument("-x", "--proxy", default=None, help="Proxy URL (http://, https://, socks5://, socks5h://)")
    p.add_argument("-H", "--header", action="append", default=[], help="Custom header 'Name: Value' (repeatable)")
    p.add_argument("-d", "--data", default=None, help="Raw request body string")
    p.add_argument("--json", dest="json_body", default=None, help="JSON request body string")
    p.add_argument("-t", "--timeout", type=float, default=30.0, help="Request timeout in seconds")
    p.add_argument("-k", "--insecure", action="store_true", help="Disable TLS certificate verification")
    p.add_argument("--info", action="store_true", help="Print response metadata (status, protocol, ECH, resumption, timing)")
    p.add_argument("--find", default=None, help="Extract first match via Rust auto-routing ($.json / XPath / CSS3)")
    p.add_argument("--find-all", default=None, help="Extract all matches via Rust auto-routing ($.json / XPath / CSS3)")
    p.add_argument("--css", default=None, help="Extract matches via Rust HTML5 CSS3 selector")
    p.add_argument("--xpath", default=None, help="Extract matches via native Rust XPath 1.0 expression")
    p.add_argument("--json-path", default=None, help="Extract value via Rust serde_json json_path")
    p.add_argument("--re", dest="regex", default=None, help="Extract matches via Rust linear-time DFA regex")
    p.add_argument("--presets", action="store_true", help="List all verified native browser presets and exit")
    p.add_argument("--version", action="version", version=f"http-tls {http_tls.__version__}")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.presets:
        for name in http_tls.supported_presets():
            print(name)
        return 0

    if not args.url:
        parser.print_help()
        return 2

    try:
        headers = _parse_headers(args.header)
        json_payload = _json.loads(args.json_body) if args.json_body is not None else None
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        with http_tls.Session(
            impersonate=args.impersonate,
            http3=args.http3 or args.http3_only,
            http3_only=args.http3_only,
            ech=args.ech,
            doh=args.doh or (args.doh_url is not None),
            doh_url=args.doh_url,
            proxy=args.proxy,
            verify=not args.insecure,
            timeout=args.timeout,
        ) as session:
            resp = session.request(
                args.method.upper(),
                args.url,
                headers=headers or None,
                data=args.data,
                json=json_payload,
            )

        if args.info:
            print(
                f"{resp.http_version} {resp.status_code} {resp.reason} | "
                f"ech_accepted={resp.ech_accepted} | tls_resumed={resp.tls_resumed} | "
                f"elapsed={resp.elapsed * 1000:.1f}ms | remote={resp.remote_addr or '-'} | url={resp.url}"
            )

        if args.find is not None:
            print(_format_value(resp.find(args.find)))
        elif args.find_all is not None:
            print(_format_value([str(x) if not isinstance(x, (str, int, float, bool, dict, list)) else x for x in resp.find_all(args.find_all)]))
        elif args.css is not None:
            print(_format_value([str(x) if not isinstance(x, str) else x for x in resp.css(args.css)]))
        elif args.xpath is not None:
            print(_format_value([str(x) if not isinstance(x, str) else x for x in resp.xpath(args.xpath)]))
        elif args.json_path is not None:
            print(_format_value(resp.json_path(args.json_path)))
        elif args.regex is not None:
            print(_format_value(resp.re(args.regex)))
        elif not args.info:
            print(resp.text)
        return 0
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
