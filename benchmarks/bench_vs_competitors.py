# Python 3 | benchmarks/bench_vs_competitors.py | Reproducible latency & throughput benchmark
"""Benchmark `http_tls` (Rust BoringSSL) against `curl_cffi`, `httpx`, and `requests`.

Run:
    python benchmarks/bench_vs_competitors.py --url https://httpbin.org/get --n 20 --concurrency 20
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import time
import tracemalloc
from typing import Awaitable, Callable, List, Optional, Tuple


def _run_sync(name: str, fn: Callable[[], int], n: int) -> Tuple[str, float, float, float]:
    fn()  # warm connection / TLS session
    latencies: List[float] = []
    tracemalloc.start()
    t_total = time.perf_counter()
    for _ in range(n):
        t0 = time.perf_counter()
        status = fn()
        assert 200 <= status < 400, f"{name} returned {status}"
        latencies.append((time.perf_counter() - t0) * 1000.0)
    total = time.perf_counter() - t_total
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return name, statistics.median(latencies), n / total, peak / 1024.0


async def _run_async(name: str, coro_factory: Callable[[], Awaitable[int]], concurrency: int) -> Tuple[str, float, float, float]:
    tracemalloc.start()
    t0 = time.perf_counter()
    statuses = await asyncio.gather(*[coro_factory() for _ in range(concurrency)])
    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert all(200 <= s < 400 for s in statuses), f"{name} failed: {statuses[:5]}"
    return name, (elapsed / concurrency) * 1000.0, concurrency / elapsed, peak / 1024.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark http_tls vs Python HTTP libraries")
    parser.add_argument("--url", default="https://www.example.com/", help="Target URL")
    parser.add_argument("--n", type=int, default=15, help="Sequential requests count")
    parser.add_argument("--concurrency", type=int, default=30, help="Concurrent async requests")
    args = parser.parse_args()

    print(f"Target: {args.url} | Sync N={args.n} | Async Concurrency={args.concurrency}\n")
    sync_rows: List[Tuple[str, float, float, float]] = []

    import http_tls
    with http_tls.Session(impersonate="chrome_149") as s:
        sync_rows.append(_run_sync("http_tls (Rust BoringSSL)", lambda: s.get(args.url).status_code, args.n))

    try:
        import curl_cffi.requests as cffi
        with cffi.Session(impersonate="chrome") as s:
            sync_rows.append(_run_sync("curl_cffi", lambda: s.get(args.url).status_code, args.n))
    except ImportError:
        pass

    try:
        import httpx
        with httpx.Client(http2=True) as s:
            sync_rows.append(_run_sync("httpx (no TLS spoof)", lambda: s.get(args.url).status_code, args.n))
    except ImportError:
        pass

    try:
        import requests
        with requests.Session() as s:
            sync_rows.append(_run_sync("requests (HTTP/1.1)", lambda: s.get(args.url).status_code, args.n))
    except ImportError:
        pass

    print("=== SEQUENTIAL (SYNC) ===")
    print(f"{'Library':<28} {'Median (ms)':>12} {'Req/sec':>10} {'Peak PyMem (KB)':>16}")
    for name, med, rps, mem in sync_rows:
        print(f"{name:<28} {med:>12.1f} {rps:>10.1f} {mem:>16.1f}")

    async def bench_async() -> None:
        rows: List[Tuple[str, float, float, float]] = []
        async with http_tls.AsyncSession(impersonate="chrome_149") as s:
            await s.get(args.url)
            rows.append(
                await _run_async(
                    "http_tls AsyncSession",
                    lambda: _status(s.get(args.url)),
                    args.concurrency,
                )
            )
        try:
            import httpx
            async with httpx.AsyncClient(http2=True) as s:
                await s.get(args.url)
                rows.append(await _run_async("httpx AsyncClient", lambda: _status(s.get(args.url)), args.concurrency))
        except ImportError:
            pass

        print("\n=== CONCURRENT (ASYNC) ===")
        print(f"{'Library':<28} {'Avg/req (ms)':>12} {'Req/sec':>10} {'Peak PyMem (KB)':>16}")
        for name, avg, rps, mem in rows:
            print(f"{name:<28} {avg:>12.1f} {rps:>10.1f} {mem:>16.1f}")

    async def _status(coro) -> int:
        r = await coro
        return r.status_code

    asyncio.run(bench_async())


if __name__ == "__main__":
    main()
