# Language: Python 3.8+ | File: benchmarks/bench_extraction.py | Runtime: http_tls
"""Reproducible benchmark comparing http_tls Pure Rust extraction against installed Python parsers."""

from __future__ import annotations

import argparse
import json
import re
import statistics
import time
from typing import Any, Callable, Dict, List

import http_tls


def build_dataset(num_cards: int) -> tuple[str, str]:
    cards: List[str] = []
    for i in range(num_cards):
        cls = "card featured" if i % 10 == 0 else ("card sold-out" if i % 7 == 0 else "card")
        cards.append(
            f'<div class="{cls}" data-id="{1000 + i}" data-cat="cat-{i % 5}">'
            f'<h2 class="title">Product Item #{i}</h2>'
            f'<span class="price">${(i % 90) + 9.99:.2f}</span>'
            f'<a class="buy" href="/item/{1000 + i}">Buy Now</a>'
            f'<p class="meta">Stock: <b>{i % 20}</b> units</p>'
            f"</div>"
        )
    html = (
        "<!doctype html><html><head><title>Bench Catalog</title></head>"
        "<body><main id='app'>" + "".join(cards) + "</main></body></html>"
    )
    json_payload = json.dumps(
        {
            "meta": {"ok": True, "total": num_cards, "nested": {"price": 9.99}},
            "items": [
                {"id": i, "name": f"item_{i}", "price": round((i % 90) + 9.99, 2), "tags": ["a", "b"]}
                for i in range(num_cards)
            ],
        }
    )
    return html, json_payload


def bench(name: str, fn: Callable[[], Any], runs: int) -> float:
    res: Any = fn()  # warmup
    times: List[float] = []
    for _ in range(runs):
        t0 = time.perf_counter()
        res = fn()
        times.append((time.perf_counter() - t0) * 1000.0)
    med = statistics.median(times)
    count = len(res) if hasattr(res, "__len__") else res
    print(f"  {name:<46} {med:7.3f} ms  (n={count})")
    return med


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark http_tls Pure Rust extraction engine")
    parser.add_argument("--cards", type=int, default=500, help="Number of HTML product cards / JSON items")
    parser.add_argument("--runs", type=int, default=30, help="Iterations per benchmark")
    args = parser.parse_args()

    html, json_str = build_dataset(args.cards)
    print(f"Dataset: HTML = {len(html) / 1024:.1f} KB ({args.cards} cards), JSON = {len(json_str) / 1024:.1f} KB\n")

    avail: Dict[str, Any] = {}
    for mod in ("bs4", "lxml.html", "parsel", "selectolax.parser"):
        try:
            avail[mod] = __import__(mod, fromlist=["*"])
        except ImportError:
            pass
    print("Detected comparators:", list(avail.keys()) or ["stdlib only"], "\n")

    print("=== 1. FULL PARSE + CSS SELECT ===")
    rust_parse = bench(
        "http_tls (Rust html5ever + dom_query)",
        lambda: http_tls.HtmlDocument(html).css("div.card a.buy::attr(href)"),
        args.runs,
    )
    if "selectolax.parser" in avail:
        HTMLParser = avail["selectolax.parser"].HTMLParser
        bench(
            "selectolax (C modest)",
            lambda: [n.attributes.get("href") for n in HTMLParser(html).css("div.card a.buy")],
            args.runs,
        )
    if "parsel" in avail:
        Selector = avail["parsel"].Selector
        bench(
            "parsel (Scrapy css::attr)",
            lambda: Selector(html).css("div.card a.buy::attr(href)").getall(),
            args.runs,
        )
    if "lxml.html" in avail:
        lxml_html = avail["lxml.html"]
        bench(
            "lxml.html + xpath (C libxml2)",
            lambda: lxml_html.fromstring(html).xpath("//div[contains(@class,'card')]//a[contains(@class,'buy')]/@href"),
            args.runs,
        )
    if "bs4" in avail:
        BS = avail["bs4"].BeautifulSoup
        bs_parse = bench(
            "BeautifulSoup (html.parser)",
            lambda: [a.get("href") for a in BS(html, "html.parser").select("div.card a.buy")],
            max(5, args.runs // 3),
        )
        print(f"    -> http_tls speedup vs BeautifulSoup (html.parser): {bs_parse / rust_parse:.1f}x")
        if "lxml.html" in avail:
            bench(
                "BeautifulSoup (lxml backend)",
                lambda: [a.get("href") for a in BS(html, "lxml").select("div.card a.buy")],
                max(5, args.runs // 2),
            )

    print("\n=== 2. QUERY ONLY (CACHED DOM: CSS3 & XPath 1.0) ===")
    doc_rust = http_tls.HtmlDocument(html)
    rust_css = bench(
        "http_tls CSS3 (div.card:not(.sold-out) a)",
        lambda: doc_rust.css("div.card:not(.sold-out) a.buy::attr(href)"),
        args.runs,
    )
    bench(
        "http_tls XPath 1.0 (contains+not /@data-id)",
        lambda: doc_rust.xpath("//div[contains(@class,'card') and not(contains(@class,'sold-out'))]/@data-id"),
        args.runs,
    )
    if "bs4" in avail:
        soup = avail["bs4"].BeautifulSoup(html, "lxml" if "lxml.html" in avail else "html.parser")
        bs_css = bench(
            "BeautifulSoup .select(:not(.sold-out))",
            lambda: [a.get("href") for a in soup.select("div.card:not(.sold-out) a.buy")],
            max(5, args.runs // 3),
        )
        print(f"    -> http_tls CSS3 speedup vs BeautifulSoup: {bs_css / rust_css:.1f}x")

    print("\n=== 3. DFA REGEX & BETWEEN_ALL ===")
    r_html = http_tls.Response(200, {}, "https://bench.example/", text=html)
    pat_str = r"\$(\d+\.\d{2})"
    pat_py = re.compile(pat_str)
    rust_re = bench("http_tls.re() (Rust cached DFA)", lambda: r_html.re(pat_str), args.runs)
    py_re = bench("Python re.compile().findall()", lambda: pat_py.findall(html), args.runs)
    bench("http_tls.between_all('href=\"', '\"')", lambda: r_html.between_all('href="', '"'), args.runs)
    print(f"    -> http_tls.re() vs Python compiled re: {py_re / rust_re:.2f}x")

    print("\n=== 4. JSON PATH (serde_json) ===")
    r_json = http_tls.Response(200, {}, "https://bench.example/", text=json_str)
    bench("http_tls.json_path('items[*].price')", lambda: r_json.json_path("items[*].price"), args.runs)
    bench("http_tls.json_path('$..price')", lambda: r_json.json_path("$..price"), args.runs)
    bench("Python json.loads + listcomp", lambda: [x["price"] for x in json.loads(json_str)["items"]], args.runs)


if __name__ == "__main__":
    main()
