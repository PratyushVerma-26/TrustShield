#!/usr/bin/env python3
"""
TrustShield Latency Benchmark Harness.

Measures p50, p95, and p99 response times over N iterations after JIT warmup.
Can benchmark:
1. HTTP endpoint latency against the running Unified Gateway (Port 8080).
2. Local Python feature extraction & inference parity.

Usage:
    python scripts/benchmark_latency.py --endpoint http://localhost:8080/api/v1/phishing/scan --iterations 1000
    python scripts/benchmark_latency.py --local-only
"""

import argparse
import json
import os
import platform
import time
import urllib.request
import urllib.error

BENCHMARK_URLS = [
    "https://www.google.com",
    "http://sbi-secure-login.verify-account.xyz/netbanking/login.php?token=99281",
    "http://192.168.1.100/admin/auth/login.html",
    "https://onlinesbi.sbi/personal/ways-to-bank/netbanking",
    "https://paytm.com/offers/cashback?id=49201&source=home",
    "http://paytm.account-verify.tk/upi/confirm?id=99",
    "https://irctc.co.in/nget/train-search?src=NDLS&dst=BCT&date=2026-10-01",
    "http://download.free-movies.top/setup.exe",
    "https://user@evil.example.org/reset-password",
    "https://hdfcbank.com/personal/banking"
]

def benchmark_endpoint(endpoint: str, iterations: int = 1000, warmup: int = 50):
    print(f"\n==========================================================================")
    print(f"            TRUSTSHIELD HTTP LATENCY BENCHMARK: {endpoint}                ")
    print(f"==========================================================================")
    print(f"Platform: {platform.system()} {platform.release()} | Python {platform.python_version()} | {os.cpu_count()} CPU cores")
    print("Note: Single-machine localhost measurement. Excludes client network latency.\n")

    # Warmup
    print(f"Warming up ({warmup} iterations)...")
    for i in range(warmup):
        target = BENCHMARK_URLS[i % len(BENCHMARK_URLS)]
        payload = json.dumps({"url": target, "context": "BENCHMARK_WARMUP"}).encode("utf-8")
        req = urllib.request.Request(endpoint, data=payload, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
        except Exception as e:
            print(f"Endpoint not reachable at {endpoint}: {e}")
            print("To run in-process Java benchmark instead, run:")
            print("  mvn test -Dtest=LatencyBenchmarkTest -pl trustshield-phishing-service")
            return None

    # Measured run
    print(f"Measuring latency over {iterations:,} iterations...")
    durations_ms = []
    for i in range(iterations):
        target = BENCHMARK_URLS[i % len(BENCHMARK_URLS)]
        payload = json.dumps({"url": target, "context": "BENCHMARK"}).encode("utf-8")
        req = urllib.request.Request(endpoint, data=payload, headers={"Content-Type": "application/json"})
        t0 = time.perf_counter()
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        durations_ms.append(elapsed_ms)

    durations_ms.sort()
    p50 = durations_ms[int(iterations * 0.50)]
    p95 = durations_ms[int(iterations * 0.95)]
    p99 = durations_ms[int(iterations * 0.99)]
    avg = sum(durations_ms) / len(durations_ms)
    min_val = durations_ms[0]
    max_val = durations_ms[-1]

    print("\n--- Benchmark Results (End-to-End HTTP + Server Processing) ---")
    print(f"  Iterations   : {iterations:,}")
    print(f"  p50 (median) : {p50:8.3f} ms")
    print(f"  p95          : {p95:8.3f} ms")
    print(f"  p99          : {p99:8.3f} ms")
    print(f"  Mean         : {avg:8.3f} ms")
    print(f"  Min / Max    : {min_val:8.3f} ms / {max_val:8.3f} ms")
    print("==========================================================================\n")

    return {"p50": p50, "p95": p95, "p99": p99, "mean": avg, "min": min_val, "max": max_val}

def main():
    parser = argparse.ArgumentParser(description="TrustShield Latency Benchmark")
    parser.add_argument("--endpoint", default="http://localhost:8080/api/v1/phishing/scan",
                        help="HTTP endpoint to benchmark")
    parser.add_argument("--iterations", type=int, default=1000,
                        help="Number of timed iterations")
    parser.add_argument("--warmup", type=int, default=50,
                        help="Number of warmup iterations")
    args = parser.parse_args()

    benchmark_endpoint(args.endpoint, iterations=args.iterations, warmup=args.warmup)

if __name__ == "__main__":
    main()
