"""Standalone production soak test for http_tls.

Spawns an in-process HTTP/1.1 keep-alive server and executes thousands of requests
across sync, Rust Tokio `gather()`, and native `AsyncSession` while tracking
throughput, error rate, Python `tracemalloc` heap delta, and OS RSS memory.

Usage:
    python benchmarks/soak_test.py --requests 5000 --concurrency 64
"""

from __future__ import annotations

import argparse
import asyncio
import gc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import threading
import time
import tracemalloc

import http_tls


class _SoakHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    _BODY = b'{"status":"ok","payload":"0123456789abcdef"}'

    def log_message(self, fmt: str, *args) -> None:
        return

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self._BODY)))
        self.end_headers()
        self.wfile.write(self._BODY)


def _rss_mb() -> float:
    try:
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        if os.name == "nt":
            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(pmc)
            hproc = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(hproc, ctypes.byref(pmc), pmc.cb):
                return pmc.WorkingSetSize / (1024.0 * 1024.0)
    except Exception:
        pass
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return usage / (1024.0 * 1024.0) if os.uname().sysname == "Darwin" else usage / 1024.0
    except Exception:
        return 0.0


class _QuietSoakServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256

    def handle_error(self, request, client_address) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Run local high-volume soak test for http_tls")
    parser.add_argument("--requests", type=int, default=3000, help="Total requests per phase")
    parser.add_argument("--concurrency", type=int, default=50, help="Concurrency level")
    args = parser.parse_args()

    server = _QuietSoakServer(("127.0.0.1", 0), _SoakHandler)
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        gc.collect()
        rss_start = _rss_mb()
        tracemalloc.start()

        # Phase 1: Parallel sync gather()
        t0 = time.perf_counter()
        with http_tls.Session(base_url=base_url, tcp_nodelay=True) as s:
            urls = [f"/soak?i={i}" for i in range(args.requests)]
            resps = s.gather(urls, concurrency=args.concurrency)
            assert len(resps) == args.requests and all(r.status_code == 200 for r in resps)
        dt_gather = time.perf_counter() - t0

        # Phase 2: Native Tokio AsyncSession
        async def _async_phase() -> None:
            sem = asyncio.Semaphore(args.concurrency)
            async with http_tls.AsyncSession(base_url=base_url, tcp_nodelay=True) as ac:
                async def _one(idx: int) -> int:
                    async with sem:
                        r = await ac.get(f"/soak?a={idx}")
                        return r.status_code

                codes = await asyncio.gather(*(_one(i) for i in range(args.requests)))
                assert len(codes) == args.requests and all(c == 200 for c in codes)

        t1 = time.perf_counter()
        asyncio.run(_async_phase())
        dt_async = time.perf_counter() - t1

        gc.collect()
        cur_py, peak_py = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rss_end = _rss_mb()

        print(f"Soak complete: {args.requests * 2} total requests, 0 errors")
        print(f"  Sync gather({args.concurrency}): {args.requests / dt_gather:,.1f} req/s ({dt_gather:.2f}s)")
        print(f"  Async Tokio({args.concurrency}): {args.requests / dt_async:,.1f} req/s ({dt_async:.2f}s)")
        print(f"  Python heap: current={cur_py / 1024:.1f} KB | peak={peak_py / 1024:.1f} KB")
        if rss_start > 0:
            print(f"  Process RSS: start={rss_start:.1f} MB -> end={rss_end:.1f} MB (delta={rss_end - rss_start:+.1f} MB)")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
