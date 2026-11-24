# Quick Start & Migration

## Drop-in for `requests`

```python
import http_tls as requests

r = requests.get("https://httpbin.org/get", timeout=10)
r.raise_for_status()
print(r.status_code, r.http_version, r.json())
```

## Drop-in for `httpx` (`Client` & `AsyncClient`)

```python
import asyncio
import http_tls as httpx

with httpx.Client(base_url="https://httpbin.org", impersonate="chrome_149") as client:
    r = client.get("/status/200")
    print(r.is_success, r.reason_phrase, r.remote_addr)

async def main():
    async with httpx.AsyncClient(impersonate="chrome_149") as client:
        r = await client.get("https://httpbin.org/get")
        print(r.status_code, len(await r.aread()))

asyncio.run(main())
```

## Drop-in for `curl_cffi`

```python
from http_tls import requests, BrowserType

r = requests.get("https://tls.peet.ws/api/all", impersonate=BrowserType.chrome149)
print(r.find("$.tls.ja4"))
```

## GIL-Free Parallel Sync Batching (`session.gather`)

```python
import http_tls

with http_tls.Session(base_url="https://httpbin.org", impersonate="chrome_149") as s:
    responses = s.gather([f"/anything?i={i}" for i in range(50)], concurrency=25)
```
