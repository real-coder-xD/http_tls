# Pure BoringSSL HTTP/3, Real ECH (`sni=encrypted`) & Session-Wide DoH

## Real ECH over UDP QUIC HTTP/3 & TCP HTTP/2

```python
import http_tls

# 1. UDP QUIC HTTP/3 + Real ECH (sni=encrypted, kex=X25519MLKEM768)
with http_tls.Session(impersonate="chrome_149", http3=True, ech=True) as s:
    r = s.get("https://cloudflare-ech.com/cdn-cgi/trace")
    assert r.http_version == "HTTP/3" and r.ech_accepted

# 2. TCP HTTP/2 + Real ECH (works even when UDP 443 is blocked)
with http_tls.Session(impersonate="chrome_149", ech=True, auto_upgrade_h3=False) as s:
    r = s.get("https://crypto.cloudflare.com/cdn-cgi/trace")
    assert r.http_version == "HTTP/2" and r.ech_accepted
```

## Session-Wide DNS-over-HTTPS (`doh=True`)

```python
with http_tls.Session(
    impersonate="chrome_149",
    doh=True,
    doh_url="https://dns.google/resolve",  # optional; defaults to Cloudflare DoH
    ech=True,
) as s:
    r = s.get("https://cloudflare-ech.com/cdn-cgi/trace")
```

## HTTP/3 over SOCKS5 UDP Associate (`RFC 1928 / RFC 1929`)

```python
with http_tls.Session(
    impersonate="chrome_149",
    http3=True,
    ech=True,
    proxy="socks5://user:pass@127.0.0.1:1080",
) as s:
    r = s.get("https://cloudflare-ech.com/cdn-cgi/trace")
```
