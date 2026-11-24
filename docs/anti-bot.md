# Anti-Bot Detection, Retries, Playwright `storage_state.json` & Solvers

```python
import http_tls
from http_tls import BestDriverSolver

# Reuse Playwright storage_state.json with automatic Rust TLS/H2 preset alignment
with http_tls.Session(
    storage_state="state.json",
    auto_referer=True,
    fetch_mode="same-origin",
) as s:
    r = s.get("https://protected.example.com/api")
    s.save_storage_state("state.json")

# Automatic challenge solver bridge (per-domain singleflight + warm browser reuse)
with http_tls.Session(
    retries=2,
    retry_on_challenge=True,
    rotate_impersonate=True,
    solver=BestDriverSolver(headless=True, keep_warm=True, click_turnstile=True),
) as s:
    r = s.get("https://protected.example.com")
    print("Detected challenge:", r.challenge)
```
