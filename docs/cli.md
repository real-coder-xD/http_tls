# Built-in CLI Debugger (`http-tls` / `python -m http_tls`)

Inspect TLS/JA4 fingerprints, Real ECH, HTTP/3, DoH, and test CSS3 / XPath 1.0 / JSON Path expressions directly from your terminal with zero extra packages:

```bash
# Inspect HTTP/3 + Real ECH + DoH metadata
http-tls https://cloudflare-ech.com/cdn-cgi/trace --http3 --ech --doh --info

# Check JA4 fingerprint for Safari 26.4 via Rust JSON Path
http-tls https://tls.peet.ws/api/all -i safari_26_4 --find "$.tls.ja4"

# Extract HTML title or XPath text directly
http-tls https://example.com --find "title::text"
http-tls https://example.com --xpath "//p/text()"

# Extract filtered JSON array items
http-tls https://api.example/items --json-path "items[?(@.price > 20)].name"

# List all 100+ verified native presets
python -m http_tls --presets
```
