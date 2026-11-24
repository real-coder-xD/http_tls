# Custom Fingerprinting, Wire Header Order & Network Routing

## Custom JA3, Akamai HTTP/2, BoringSSL `tls_options` & `header_order`

```python
import http_tls

with http_tls.Session(
    ja3="771,4865-4866-4867-49195-49199,0-23-65281,29-23-24,0",
    akamai_h2="1:65536;2:0;4:2097152;6:262144|10420225|0|m,s,a,p",
    tls_options={
        "alpn": ["h2", "http/1.1"],
        "grease_enabled": True,
        "permute_extensions": True,
        "certificate_compressors": ["brotli", "zlib", "zstd"],
    },
    header_order=["Host", "Connection", "User-Agent", "Accept"],
) as s:
    r = s.get("https://tls.peet.ws/api/all")
```

## Custom Origin IP (`resolve`), IPv6 `/64` Rotation & mTLS

```python
with http_tls.Session(
    resolve={"api.example.com": "93.184.216.34"},
    local_address="2001:db8::42",
    verify="/path/to/custom_ca.pem",
    cert=("client.crt", "client.key"),
    keylog_file="sslkeys.log",
) as s:
    r = s.get("https://api.example.com/health")
```
