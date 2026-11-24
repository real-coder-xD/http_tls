# Pure Rust Extraction Engine (HTML5 CSS3, XPath 1.0, JSON Path & DFA Regex)

Every `Response` ships with a **100% Pure Rust** extraction layer (`src/extract.rs`) requiring zero external Python packages (`beautifulsoup4`, `lxml`, `parsel`, `selectolax`, `jsonpath-ng`).

## CSS3, XPath 1.0, DOM Navigation & Unified `find()`

```python
import http_tls

r = http_tls.get("https://shop.example/catalog")

# CSS3 (+ :has(), :contains(), :not(), Scrapy ::text / ::attr(), BS4 select/select_one)
title = r.select_one("title::text", default="")
links = r.css("div.card:not(.sold-out) a.buy::attr(href)")
card = r.select_one("div.card.featured")
if card is not None:
    print(card.own_text.strip(), card.get_text(" | "))
    print(card.attrib, card.parent.tag, card.next_sibling["data-id"])
    print(r.urljoin(card.find(".//a/@href")))

# Native Rust XPath 1.0
ids = r.xpath("//div[contains(@class, 'card') and not(contains(@class, 'sold-out'))]/@data-id")
next_h2 = r.xpath_first("//h2[normalize-space(.)='Alpha']/following::h2[1]/text()")
last_id = r.xpath_first("(//div[contains(@class, 'card')])[last()]/@data-id")

# Cached DFA Regex & Delimiter Slicing
token = r.re_first(r'__TOKEN__\s*=\s*"([^"]+)"', default="")
all_hrefs = r.between_all('href="', '"')
```

## Cached JSON Path (`serde_json` + Filter Predicates)

```python
api = http_tls.get("https://api.example/v1/items")

# Lazily parsed once into Rust JsonDocument (`r.json_doc`) -> 0.017 ms repeated queries
names = api.json_path("items[*].name")
top2 = api.json_path("items[0:2].name")
in_stock_expensive = api.json_path("items[?(@.price > 15 && @.in_stock == true)].name")
all_prices = api.json_path("$..price")
last_id = api.find("$.items[-1].id", default=0)
```

## Verified Benchmarks (`python benchmarks/bench_extraction.py`)

| Workload (105.7 KB HTML / 500 cards) | `http_tls` (Rust) | Baseline | Speedup |
| :--- | ---: | ---: | :--- |
| Full HTML5 parse + CSS3 (`500 hrefs`) | **2.82 ms** | `BeautifulSoup (html.parser)`: 58.31 ms | **20.7x** |
| Cached DOM CSS3 (`:not(.sold-out)`) | **0.093 ms** | `BeautifulSoup .select()`: 7.05 ms | **75.6x** |
| Cached JSON Path `items[*].price` | **0.017 ms** | `json.loads()` + listcomp: 0.283 ms | **16.6x** |
| Cached Recursive JSON Path `$..price` | **0.028 ms** | `json.loads()` + listcomp: 0.283 ms | **10.1x** |
| `between_all()` (`500 hrefs`) | **0.064 ms** | Python `re.compile().findall()`: 0.079 ms | **1.23x** |
