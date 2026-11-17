#!/usr/bin/env python3
"""Build reproducible evaluation dataset from feeds + Tranco + handwritten cases.

Assembles data/eval/eval_manifest.csv with columns:
    url, label, source, date, registrable_domain, split

Splits by registrable domain (GroupShuffleSplit) to avoid domain leakage:
    train 60% / val 20% / test 20% (locked, hash recorded in journal)

Leakage avoidance (spec section 11):
1. Path artefact: For Tranco benign URLs, fetch homepage and sample real internal
   links where possible. Mark bare hosts vs real links.
2. Feed-identity: Don't encode which feed in features. Mix feeds.
3. Domain leakage: Split by registrable_domain so same domain never in train+test.
4. Time leakage: Where dates exist, time-based split view recorded separately.
5. Dead URLs: All URLs in manifest; live subset evaluated separately.

Usage:
    python -m scripts.build_eval_set --tranco-limit 1000 --sample-paths 100

Output:
    data/eval/eval_manifest.csv (600+ rows, gitignored)
    data/eval/tricky_cases.csv (20+ handwritten, committed)
"""

import argparse
import csv
import hashlib
import json
import logging
import random
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    import httpx
    import tldextract
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install httpx tldextract beautifulsoup4")
    raise

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Repo root
BACKEND = Path(__file__).parent.parent
DATA = BACKEND / "data"
EVAL_DIR = DATA / "eval"
RAW_DIR = DATA / "raw"

# Feed licensing compliance
FEED_TERMS = {
    "openphish": "Community feed: free for personal/academic research; no commercial use; no redistribution without written permission",
    "urlhaus": "Free for qualifying non-profit; no AI training without written consent; Auth-Key may be required",
    "tranco": "Free research ranking list; no separate license stated on official site; list ID and attribution retained",
}

# Handwritten tricky cases (Indian context, edge cases)
TRICKY_CASES = [
    {
        "url": "http://sbi-secure-login-verify.xyz/kyc",
        "label": 1,
        "source": "handwritten",
        "note": "SBI typosquat, young domain, sensitive path",
    },
    {
        "url": "https://icici-netbanking-kyc.online/login",
        "label": 1,
        "source": "handwritten",
        "note": "ICICI typosquat, risky TLD",
    },
    {
        "url": "https://paytm-refund-claim.site/verify",
        "label": 1,
        "source": "handwritten",
        "note": "Paytm fake refund",
    },
    {
        "url": "upi://collect?pa=random123@ybl&pn=Cashback&am=5000&tn=REWARD",
        "label": 1,
        "source": "handwritten",
        "note": "UPI collect disguised as reward",
    },
    {
        "url": "https://bit.ly/3fake12",
        "label": 1,
        "source": "handwritten",
        "note": "Shortener hiding destination",
    },
    {
        "url": "https://eviluser.github.io/phishing-page",
        "label": 1,
        "source": "handwritten",
        "note": "Shared hosting phishing",
    },
    {
        "url": "http://192.168.1.100/admin",
        "label": 1,
        "source": "handwritten",
        "note": "Private IP (should be blocked by netguard)",
    },
    {
        "url": "https://secure-login-verify-account-update.xyz",
        "label": 1,
        "source": "handwritten",
        "note": "Keyword stuffing, long domain",
    },
    {
        "url": "https://xn--80ahgue4b.xyz",
        "label": 1,
        "source": "handwritten",
        "note": "Punycode domain",
    },
    {
        "url": "https://www.google.com",
        "label": 0,
        "source": "handwritten",
        "note": "Top benign site",
    },
    {
        "url": "https://www.wikipedia.org",
        "label": 0,
        "source": "handwritten",
        "note": "Top benign site",
    },
    {
        "url": "https://www.sbi.co.in",
        "label": 0,
        "source": "handwritten",
        "note": "Official SBI site",
    },
    {
        "url": "https://www.icicibank.com",
        "label": 0,
        "source": "handwritten",
        "note": "Official ICICI Bank",
    },
    {
        "url": "https://paytm.com",
        "label": 0,
        "source": "handwritten",
        "note": "Official Paytm",
    },
    {
        "url": "https://github.com/torvalds/linux",
        "label": 0,
        "source": "handwritten",
        "note": "Popular repo, path present (benign)",
    },
    {
        "url": "https://stackoverflow.com/questions/12345/some-question",
        "label": 0,
        "source": "handwritten",
        "note": "Popular site with long path",
    },
    {
        "url": "https://small-legit-shop.co.in/products",
        "label": 0,
        "source": "handwritten",
        "note": "Small benign site (simulated)",
    },
    {
        "url": "https://newstartup2024.com/about",
        "label": 0,
        "source": "handwritten",
        "note": "Young but legitimate site (simulated)",
    },
    {
        "url": "https://my-personal-blog.vercel.app",
        "label": 0,
        "source": "handwritten",
        "note": "Shared hosting, benign",
    },
    {
        "url": "https://example.com",
        "label": 0,
        "source": "handwritten",
        "note": "Reserved example domain",
    },
]


def fetch_openphish_urls(terms_acknowledged: bool = False) -> list[dict[str, Any]]:
    """Fetch OpenPhish community feed (requires explicit terms acknowledgment)."""
    if not terms_acknowledged:
        logger.warning(
            "OpenPhish feed skipped: requires explicit --acknowledge-openphish-terms"
        )
        logger.warning(f"Terms: {FEED_TERMS['openphish']}")
        return []

    url = "https://openphish.com/feed.txt"
    logger.info(f"Fetching OpenPhish feed from {url}")
    try:
        resp = httpx.get(url, timeout=30, follow_redirects=True)
        resp.raise_for_status()
        urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
        logger.info(f"Fetched {len(urls)} URLs from OpenPhish")
        return [
            {
                "url": u,
                "label": 1,
                "source": "openphish",
                "date": datetime.now(timezone.utc).isoformat(),
            }
            for u in urls
        ]
    except Exception as e:
        logger.error(f"Failed to fetch OpenPhish: {e}")
        return []


def fetch_urlhaus_urls(auth_key: str | None = None) -> list[dict[str, Any]]:
    """Fetch URLhaus malware URLs (may require Auth-Key)."""
    if not auth_key:
        logger.warning("URLhaus feed skipped: no --urlhaus-key provided")
        logger.warning(f"Terms: {FEED_TERMS['urlhaus']}")
        return []

    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"
    logger.info(f"Fetching URLhaus feed from {url}")
    try:
        headers = {"Auth-Key": auth_key} if auth_key else {}
        resp = httpx.post(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok":
            logger.warning(f"URLhaus query status: {data.get('query_status')}")
            return []
        urls_data = data.get("urls", [])
        logger.info(f"Fetched {len(urls_data)} URLs from URLhaus")
        return [
            {
                "url": item["url"],
                "label": 1,
                "source": "urlhaus",
                "date": item.get("dateadded", ""),
            }
            for item in urls_data
            if "url" in item
        ]
    except Exception as e:
        logger.error(f"Failed to fetch URLhaus: {e}")
        return []


def fetch_tranco_top(limit: int = 1000) -> list[dict[str, Any]]:
    """Fetch Tranco top-N domains (benign sample)."""
    # Use the latest daily list (permanent URL)
    # This is the standard 1M list averaged over 30 days from all providers
    url = "https://tranco-list.eu/top-1m.csv.zip"
    logger.info(f"Fetching Tranco latest top-1M list, will use top {limit}")

    try:
        resp = httpx.get(url, timeout=60, follow_redirects=True)
        resp.raise_for_status()

        # Handle both plain CSV and potential ZIP
        content = resp.content
        if content.startswith(b"PK"):  # ZIP magic bytes
            import zipfile
            from io import BytesIO

            with zipfile.ZipFile(BytesIO(content)) as zf:
                names = zf.namelist()
                if names:
                    with zf.open(names[0]) as f:
                        lines = f.read().decode("utf-8").splitlines()
                else:
                    lines = []
        else:
            lines = content.decode("utf-8").splitlines()

        domains = []
        for line in lines[:limit]:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                rank, domain = parts[0], parts[1]
                domains.append(
                    {
                        "url": f"https://{domain}",  # Will be marked as bare host
                        "label": 0,
                        "source": "tranco",
                        "date": "",
                        "rank": int(rank),
                        "is_bare_host": True,
                    }
                )

        logger.info(f"Fetched {len(domains)} Tranco domains")
        return domains

    except Exception as e:
        logger.error(f"Failed to fetch Tranco: {e}")
        return []


def sample_real_links(
    tranco_domains: list[dict[str, Any]], sample_count: int = 100
) -> list[dict[str, Any]]:
    """Fetch homepages of Tranco domains and sample real internal links.
    
    This mitigates the path artefact: phishing URLs have paths, but Tranco
    domains as bare hosts would teach 'has_path => phishing'. By sampling
    real links from benign sites, we balance the feature distribution.
    """
    logger.info(
        f"Sampling real links from {min(sample_count, len(tranco_domains))} Tranco domains"
    )

    enriched = []
    client = httpx.Client(timeout=10, follow_redirects=True)

    # Stratify by rank band to get diverse sites
    bands = defaultdict(list)
    for d in tranco_domains:
        rank = d.get("rank", 999999)
        if rank <= 100:
            bands["top100"].append(d)
        elif rank <= 1000:
            bands["top1k"].append(d)
        else:
            bands["rest"].append(d)

    sample_per_band = sample_count // 3
    to_fetch = (
        random.sample(bands["top100"], min(sample_per_band, len(bands["top100"])))
        + random.sample(bands["top1k"], min(sample_per_band, len(bands["top1k"])))
        + random.sample(bands["rest"], min(sample_per_band, len(bands["rest"])))
    )

    for domain_entry in to_fetch:
        url = domain_entry["url"]
        try:
            resp = client.get(url, timeout=10)
            if resp.status_code != 200:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            links = []
            for a in soup.find_all("a", href=True):
                href = a["href"]
                full_url = urljoin(url, href)
                parsed = urlparse(full_url)
                # Only same-domain http(s) links with paths
                if (
                    parsed.scheme in ("http", "https")
                    and parsed.netloc == urlparse(url).netloc
                    and parsed.path
                    and parsed.path != "/"
                ):
                    links.append(full_url)

            if links:
                # Sample up to 2 links per domain
                sampled = random.sample(links, min(2, len(links)))
                for link in sampled:
                    enriched.append(
                        {
                            "url": link,
                            "label": 0,
                            "source": "tranco_sampled",
                            "date": "",
                            "rank": domain_entry.get("rank"),
                            "is_bare_host": False,
                        }
                    )

            time.sleep(0.5)  # Polite delay

        except Exception as e:
            logger.debug(f"Could not fetch {url}: {e}")
            continue

    client.close()
    logger.info(f"Sampled {len(enriched)} real links from benign sites")
    return enriched


def add_registrable_domains(rows: list[dict[str, Any]]) -> None:
    """Add registrable_domain column to all rows for splitting."""
    extractor = tldextract.TLDExtract(include_psl_private_domains=True)

    for row in rows:
        url = row["url"]
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path.split("/")[0]  # UPI case
        extracted = extractor(host)
        registrable = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        row["registrable_domain"] = registrable or host


def split_by_domain(
    rows: list[dict[str, Any]], train_ratio: float = 0.6, val_ratio: float = 0.2, random_seed: int = 42
) -> None:
    """Split rows by registrable_domain (GroupShuffleSplit) to avoid domain leakage.
    
    Assigns 'split' field: 'train', 'val', or 'test'.
    """
    random.seed(random_seed)

    # Group by domain
    domain_to_rows = defaultdict(list)
    for row in rows:
        domain_to_rows[row["registrable_domain"]].append(row)

    domains = list(domain_to_rows.keys())
    random.shuffle(domains)

    n_domains = len(domains)
    n_train = int(n_domains * train_ratio)
    n_val = int(n_domains * val_ratio)

    train_domains = set(domains[:n_train])
    val_domains = set(domains[n_train : n_train + n_val])
    test_domains = set(domains[n_train + n_val :])

    for row in rows:
        domain = row["registrable_domain"]
        if domain in train_domains:
            row["split"] = "train"
        elif domain in val_domains:
            row["split"] = "val"
        else:
            row["split"] = "test"

    logger.info(
        f"Split: {len(train_domains)} train domains, {len(val_domains)} val, {len(test_domains)} test"
    )
    train_count = sum(1 for r in rows if r["split"] == "train")
    val_count = sum(1 for r in rows if r["split"] == "val")
    test_count = sum(1 for r in rows if r["split"] == "test")
    logger.info(
        f"Split: {train_count} train rows, {val_count} val, {test_count} test"
    )


def compute_test_hash(rows: list[dict[str, Any]]) -> str:
    """Compute SHA-256 hash of test split URLs (sealed, for journal)."""
    test_urls = sorted([r["url"] for r in rows if r["split"] == "test"])
    test_str = "\n".join(test_urls)
    return hashlib.sha256(test_str.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Build evaluation dataset")
    parser.add_argument("--tranco-limit", type=int, default=1000, help="Tranco top-N")
    parser.add_argument(
        "--sample-paths", type=int, default=100, help="Sample real links from Tranco"
    )
    parser.add_argument(
        "--acknowledge-openphish-terms",
        action="store_true",
        help="Acknowledge OpenPhish community feed terms",
    )
    parser.add_argument("--urlhaus-key", help="URLhaus Auth-Key (optional)")
    parser.add_argument("--random-seed", type=int, default=42, help="Random seed")

    args = parser.parse_args()

    # Create directories
    EVAL_DIR.mkdir(parents=True, exist_ok=True)

    # Collect data
    logger.info("Building evaluation dataset...")

    malicious = []
    malicious.extend(fetch_openphish_urls(args.acknowledge_openphish_terms))
    malicious.extend(fetch_urlhaus_urls(args.urlhaus_key))
    logger.info(f"Total malicious URLs: {len(malicious)}")

    benign = fetch_tranco_top(args.tranco_limit)
    if args.sample_paths > 0:
        benign.extend(sample_real_links(benign, args.sample_paths))
    logger.info(f"Total benign URLs: {len(benign)}")

    # Add handwritten tricky cases
    handwritten = [
        {
            "url": case["url"],
            "label": case["label"],
            "source": case["source"],
            "date": "",
            "note": case.get("note", ""),
        }
        for case in TRICKY_CASES
    ]
    logger.info(f"Total handwritten cases: {len(handwritten)}")

    # Combine
    all_rows = malicious + benign + handwritten

    # Deduplicate by URL
    seen_urls = set()
    deduped = []
    for row in all_rows:
        url_normalized = row["url"].lower().strip()
        if url_normalized not in seen_urls:
            seen_urls.add(url_normalized)
            deduped.append(row)
    logger.info(f"After deduplication: {len(deduped)} URLs")

    # Add registrable domains
    add_registrable_domains(deduped)

    # Split by domain
    split_by_domain(deduped, random_seed=args.random_seed)

    # Compute test hash (sealed split)
    test_hash = compute_test_hash(deduped)
    logger.info(f"Test split hash (sealed): {test_hash[:16]}...")

    # Write manifest
    manifest_path = EVAL_DIR / "eval_manifest.csv"
    fieldnames = ["url", "label", "source", "date", "registrable_domain", "split"]
    if any("note" in r for r in deduped):
        fieldnames.append("note")
    if any("is_bare_host" in r for r in deduped):
        fieldnames.append("is_bare_host")
    if any("rank" in r for r in deduped):
        fieldnames.append("rank")

    with open(manifest_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(deduped)

    logger.info(f"Wrote {len(deduped)} rows to {manifest_path}")

    # Write tricky cases separately (committed)
    tricky_path = EVAL_DIR / "tricky_cases.csv"
    with open(tricky_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["url", "label", "source", "note"], extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(handwritten)
    logger.info(f"Wrote {len(handwritten)} tricky cases to {tricky_path}")

    # Write metadata
    metadata = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_rows": len(deduped),
        "malicious": sum(1 for r in deduped if r["label"] == 1),
        "benign": sum(1 for r in deduped if r["label"] == 0),
        "train": sum(1 for r in deduped if r["split"] == "train"),
        "val": sum(1 for r in deduped if r["split"] == "val"),
        "test": sum(1 for r in deduped if r["split"] == "test"),
        "test_split_hash": test_hash,
        "random_seed": args.random_seed,
        "feed_terms": FEED_TERMS,
    }
    metadata_path = EVAL_DIR / "eval_metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"Wrote metadata to {metadata_path}")

    logger.info("Evaluation dataset build complete.")
    print(f"\nTest split sealed hash: {test_hash}")
    print("Record this hash in the journal. Do not tune on the test split.")


if __name__ == "__main__":
    main()
