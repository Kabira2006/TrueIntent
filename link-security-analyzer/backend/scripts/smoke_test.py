#!/usr/bin/env python3
"""Smoke test: verify the system works on real and risky links.

Posts 20 canned links to a running stack, polls to completion, prints results,
and exits non-zero if classic benign sites are flagged DANGEROUS or known
risky test cases are flagged LIKELY_SAFE.

Usage:
    python scripts/smoke_test.py [--api-base http://localhost:8000]
"""

import argparse
import sys
import time
from typing import Any

import httpx


# 10 benign links that should NOT be flagged DANGEROUS
BENIGN_LINKS = [
    "https://www.google.com",
    "https://en.wikipedia.org",
    "https://www.sbi.co.in",  # State Bank of India
    "https://www.irctc.co.in",  # Indian Railways
    "https://github.com",
    "https://www.amazon.in",
    "https://www.flipkart.com",
    "https://www.microsoft.com",
    "https://www.cloudflare.com",
    "https://www.python.org",
]

# 10 risky links that should NOT be flagged LIKELY_SAFE
# Mix of typosquats, suspicious patterns, and UPI collect
RISKY_LINKS = [
    "http://sbi-secure-login-verify.xyz",  # Typosquat (doesn't exist but should trigger lexical)
    "http://irctc-ticket-booking.online",  # Typosquat
    "http://amazon-refund-claim.site",  # Suspicious pattern
    "http://verify-your-account-now.com",  # Urgency keywords
    "http://secure-banking-portal.info",  # Generic suspicious
    "http://click-here-for-prize.win",  # Prize scam pattern
    "http://update-payment-details.xyz",  # Payment urgency
    "http://government-subsidy-claim.online",  # Government impersonation
    "upi://pay?pa=scammer@paytm&am=5000&tn=refund",  # UPI collect request
    "http://192-168-1-1.example.com",  # Suspicious domain pattern
]


def submit_scan(api_base: str, url: str, timeout: float = 30.0) -> dict[str, Any]:
    """Submit a scan and poll until complete or timeout."""
    client = httpx.Client(timeout=timeout)
    
    # Submit scan
    submit_resp = client.post(
        f"{api_base}/api/v1/scan",
        json={"input": url}
    )
    
    if submit_resp.status_code != 202:
        return {
            "url": url,
            "error": f"Submit failed: {submit_resp.status_code}",
            "verdict": "ERROR",
            "score": 0,
            "coverage": "unknown",
            "elapsed": 0.0,
        }
    
    scan_data = submit_resp.json()
    poll_url = scan_data.get("poll_url", "")
    
    if not poll_url:
        return {
            "url": url,
            "error": "No poll_url in response",
            "verdict": "ERROR",
            "score": 0,
            "coverage": "unknown",
            "elapsed": 0.0,
        }
    
    # Poll until complete
    start_time = time.time()
    max_polls = 60  # 60 polls at 1s = 60s max
    
    for poll_attempt in range(max_polls):
        time.sleep(1.0)
        
        try:
            poll_resp = client.get(f"{api_base}{poll_url}")
            
            if poll_resp.status_code != 200:
                continue
                
            result = poll_resp.json()
            status = result.get("status", "")
            
            if status in ("COMPLETED", "complete_partial", "FAILED"):
                elapsed = time.time() - start_time
                verdict = result.get("verdict", "UNKNOWN")
                score = result.get("risk_score", 0)
                coverage = result.get("coverage", {}).get("level", "unknown")
                
                return {
                    "url": url,
                    "verdict": verdict,
                    "score": score,
                    "coverage": coverage,
                    "elapsed": elapsed,
                    "status": status,
                }
        except Exception as e:
            continue
    
    # Timeout
    elapsed = time.time() - start_time
    return {
        "url": url,
        "error": f"Timeout after {elapsed:.1f}s",
        "verdict": "TIMEOUT",
        "score": 0,
        "coverage": "unknown",
        "elapsed": elapsed,
    }


def print_results_table(results: list[dict[str, Any]]) -> None:
    """Print results in a formatted table."""
    print("\n" + "=" * 110)
    print(f"{'URL':<50} {'VERDICT':<15} {'SCORE':<8} {'COVERAGE':<12} {'TIME(s)':<8}")
    print("=" * 110)
    
    for r in results:
        url = r["url"][:48] + ".." if len(r["url"]) > 50 else r["url"]
        verdict = r.get("verdict", "ERROR")
        score = r.get("score", 0)
        coverage = r.get("coverage", "unknown")
        elapsed = r.get("elapsed", 0.0)
        
        # Color coding (won't show in all terminals)
        if verdict == "DANGEROUS":
            verdict_display = f"🔴 {verdict}"
        elif verdict == "SUSPICIOUS":
            verdict_display = f"🟡 {verdict}"
        elif verdict == "LIKELY_SAFE":
            verdict_display = f"🟢 {verdict}"
        else:
            verdict_display = verdict
        
        print(f"{url:<50} {verdict_display:<15} {score:<8} {coverage:<12} {elapsed:<8.1f}")
        
        if "error" in r:
            print(f"  ↳ Error: {r['error']}")
    
    print("=" * 110 + "\n")


def check_failures(results: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Check for unacceptable results.
    
    Returns (false_alarms, misses) where:
    - false_alarms: benign sites flagged DANGEROUS
    - misses: risky sites flagged LIKELY_SAFE
    """
    false_alarms = []
    misses = []
    
    for r in results:
        url = r["url"]
        verdict = r.get("verdict", "ERROR")
        
        # Check benign sites
        if any(benign in url for benign in BENIGN_LINKS):
            if verdict == "DANGEROUS":
                false_alarms.append(f"{url} → {verdict} (expected: not DANGEROUS)")
        
        # Check risky sites
        if any(risky in url for risky in RISKY_LINKS):
            if verdict == "LIKELY_SAFE":
                misses.append(f"{url} → {verdict} (expected: not LIKELY_SAFE)")
    
    return false_alarms, misses


def main() -> int:
    """Run smoke test and return exit code."""
    parser = argparse.ArgumentParser(description="Smoke test for TrueIntent link analyzer")
    parser.add_argument(
        "--api-base",
        default="http://localhost:8000",
        help="API base URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Timeout per scan in seconds (default: 60)"
    )
    args = parser.parse_args()
    
    print(f"\n🧪 TrueIntent Smoke Test")
    print(f"API: {args.api_base}")
    print(f"Testing {len(BENIGN_LINKS)} benign + {len(RISKY_LINKS)} risky links\n")
    
    # Check API is reachable
    try:
        resp = httpx.get(f"{args.api_base}/healthz", timeout=5.0)
        if resp.status_code not in (200, 503):  # 503 = degraded (sandbox unavailable)
            print(f"❌ API health check failed: {resp.status_code}")
            print("Make sure the stack is running: docker compose up")
            return 1
        if resp.status_code == 503:
            health_data = resp.json()
            print(f"⚠️  API is degraded: {health_data}")
            print("    (Sandbox may be unavailable, continuing with fast-path checks)\n")
    except Exception as e:
        print(f"❌ Cannot reach API: {e}")
        print("Make sure the stack is running: docker compose up")
        return 1
    
    print("✅ API is reachable\n")
    
    # Test benign links
    print("Testing benign links (should not be DANGEROUS)...")
    benign_results = []
    for url in BENIGN_LINKS:
        print(f"  Scanning: {url}")
        result = submit_scan(args.api_base, url, args.timeout)
        benign_results.append(result)
    
    # Test risky links
    print("\nTesting risky links (should not be LIKELY_SAFE)...")
    risky_results = []
    for url in RISKY_LINKS:
        print(f"  Scanning: {url}")
        result = submit_scan(args.api_base, url, args.timeout)
        risky_results.append(result)
    
    # Print results
    all_results = benign_results + risky_results
    print_results_table(all_results)
    
    # Check for failures
    false_alarms, misses = check_failures(all_results)
    
    # Summary
    print(f"\n📊 Summary:")
    print(f"  Total scans: {len(all_results)}")
    print(f"  Benign tested: {len(benign_results)}")
    print(f"  Risky tested: {len(risky_results)}")
    print(f"  False alarms (benign → DANGEROUS): {len(false_alarms)}")
    print(f"  Misses (risky → LIKELY_SAFE): {len(misses)}")
    
    # Report failures
    exit_code = 0
    
    if false_alarms:
        print(f"\n❌ FALSE ALARMS DETECTED:")
        for fa in false_alarms:
            print(f"  {fa}")
        exit_code = 1
    
    if misses:
        print(f"\n❌ MISSES DETECTED:")
        for miss in misses:
            print(f"  {miss}")
        exit_code = 1
    
    if exit_code == 0:
        print(f"\n✅ SMOKE TEST PASSED")
        print("All benign sites avoided DANGEROUS verdict")
        print("All risky sites avoided LIKELY_SAFE verdict")
    else:
        print(f"\n❌ SMOKE TEST FAILED")
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
