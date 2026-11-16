#!/usr/bin/env python3
"""Download and refresh reputation feeds: Tranco, OpenPhish, URLhaus.

Usage:
    python -m scripts.download_feeds [--refresh]

Downloads to data/raw/ (gitignored) and records metadata in the feed_meta table.
Each feed source has bounded timeouts and graceful failure; one feed failing never
crashes the whole script.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import select, text

from app.config import get_settings
from app.db.models import FeedMeta
from app.db.session import get_sync_session

# Python 3.9 compatibility
UTC = timezone.utc

USER_AGENT = "TrueIntent-LinkAnalyzer/0.1 (+https://github.com/Kabira2006/TrueIntent)"
TIMEOUT_SECONDS = 30.0

# Output directory for raw feed files (gitignored)
DATA_RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"


def _download_url(url: str, auth_key: str | None = None) -> tuple[bytes, str]:
    """Download content from URL with timeout; return (content, error_msg)."""
    headers = {"User-Agent": USER_AGENT}
    if auth_key:
        headers["Auth-Key"] = auth_key
    
    try:
        with httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=True) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()
            return response.content, ""
    except httpx.TimeoutException:
        return b"", f"timeout after {TIMEOUT_SECONDS}s"
    except httpx.HTTPStatusError as exc:
        return b"", f"HTTP {exc.response.status_code}"
    except Exception as exc:  # noqa: BLE001
        return b"", f"error: {type(exc).__name__}"


def download_tranco(session: Any) -> dict[str, Any]:
    """Download Tranco top-1M list."""
    print("Downloading Tranco top-1M list...")
    
    # Tranco list ID: Use the most recent stable list
    # Format: https://tranco-list.eu/download/XXXXX/1000000
    # For reproducibility, we use a fixed recent list ID
    list_id = "9MNLX"  # Recent stable list (update periodically)
    url = f"https://tranco-list.eu/download/{list_id}/1000000"
    
    content, error = _download_url(url)
    if error:
        print(f"  ❌ Tranco download failed: {error}")
        return {
            "source": "tranco",
            "status": "failed",
            "error": error,
            "url": url,
        }
    
    # Save to data/raw/
    DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)
    output_path = DATA_RAW_DIR / f"tranco_{list_id}.csv"
    output_path.write_bytes(content)
    
    # Count lines
    line_count = len(content.decode("utf-8", errors="ignore").strip().split("\n"))
    size_mb = len(content) / (1024 * 1024)
    
    # Record metadata
    meta = FeedMeta(
        source="tranco",
        fetched_at=datetime.now(UTC),
        row_count=line_count,
        license_note="Tranco list; free for research and non-commercial use",
        detail={"list_id": list_id, "url": url},
    )
    session.merge(meta)
    session.commit()
    
    print(f"  ✓ Downloaded {line_count:,} domains ({size_mb:.1f} MB)")
    return {
        "source": "tranco",
        "status": "success",
        "row_count": line_count,
        "list_id": list_id,
        "path": str(output_path),
    }


def download_openphish(session: Any) -> dict[str, Any]:
    """Download OpenPhish community feed."""
    print("Downloading OpenPhish community feed...")
    
    url = "https://openphish.com/feed.txt"
    content, error = _download_url(url)
    if error:
        print(f"  ❌ OpenPhish download failed: {error}")
        return {
            "source": "openphish",
            "status": "failed",
            "error": error,
            "url": url,
        }
    
    # Save to data/raw/
    DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    output_path = DATA_RAW_DIR / f"openphish_{timestamp}.txt"
    output_path.write_bytes(content)
    
    # Count URLs
    urls = [
        line.strip()
        for line in content.decode("utf-8", errors="ignore").split("\n")
        if line.strip() and line.strip().startswith("http")
    ]
    url_count = len(urls)
    
    # Record metadata
    meta = FeedMeta(
        source="openphish",
        fetched_at=datetime.now(UTC),
        row_count=url_count,
        license_note="OpenPhish community feed; free for non-commercial use",
        detail={"url": url},
    )
    session.merge(meta)
    session.commit()
    
    print(f"  ✓ Downloaded {url_count:,} phishing URLs")
    return {
        "source": "openphish",
        "status": "success",
        "row_count": url_count,
        "path": str(output_path),
    }


def download_urlhaus(session: Any, auth_key: str | None) -> dict[str, Any]:
    """Download URLhaus CSV export.
    
    URLhaus requires a free API key from abuse.ch.
    Get one at: https://urlhaus.abuse.ch/api/
    """
    print("Downloading URLhaus malware URL feed...")
    
    if not auth_key:
        print("  ⚠️  ABUSECH_AUTH_KEY not set; skipping URLhaus")
        return {
            "source": "urlhaus",
            "status": "skipped",
            "error": "no_api_key",
        }
    
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    content, error = _download_url(url, auth_key=auth_key)
    if error:
        print(f"  ❌ URLhaus download failed: {error}")
        return {
            "source": "urlhaus",
            "status": "failed",
            "error": error,
            "url": url,
        }
    
    # Save to data/raw/
    DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    output_path = DATA_RAW_DIR / f"urlhaus_{timestamp}.csv"
    output_path.write_bytes(content)
    
    # Count URLs (skip comment lines starting with #)
    lines = [
        line
        for line in content.decode("utf-8", errors="ignore").split("\n")
        if line.strip() and not line.strip().startswith("#")
    ]
    url_count = len(lines)
    
    # Record metadata
    meta = FeedMeta(
        source="urlhaus",
        fetched_at=datetime.now(UTC),
        row_count=url_count,
        license_note="URLhaus; free for non-commercial use with API key",
        detail={"url": url},
    )
    session.merge(meta)
    session.commit()
    
    print(f"  ✓ Downloaded {url_count:,} malware URLs")
    return {
        "source": "urlhaus",
        "status": "success",
        "row_count": url_count,
        "path": str(output_path),
    }


def download_all() -> list[dict[str, Any]]:
    """Download all feeds and return results summary."""
    settings = get_settings()
    results: list[dict[str, Any]] = []
    
    print("\n🔄 Downloading reputation feeds...")
    print(f"Output directory: {DATA_RAW_DIR}\n")
    
    with next(get_sync_session()) as session:
        # Tranco (no key needed)
        results.append(download_tranco(session))
        
        # OpenPhish (no key needed)
        results.append(download_openphish(session))
        
        # URLhaus (needs abuse.ch API key)
        urlhaus_key = getattr(settings, "abusech_auth_key", None)
        results.append(download_urlhaus(session, urlhaus_key))
    
    # Summary
    print("\n📊 Summary:")
    for result in results:
        source = result["source"]
        status = result["status"]
        if status == "success":
            count = result.get("row_count", 0)
            print(f"  {source:12s} ✓ {count:,} entries")
        elif status == "skipped":
            print(f"  {source:12s} ⚠️  skipped ({result.get('error', 'unknown')})")
        else:
            print(f"  {source:12s} ❌ failed ({result.get('error', 'unknown')})")
    
    return results


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description="Download reputation feeds")
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Refresh feeds (same as default behavior)",
    )
    args = parser.parse_args()
    
    try:
        results = download_all()
        
        # Exit code: 0 if at least one feed succeeded, 1 if all failed
        successful = sum(1 for r in results if r["status"] == "success")
        if successful == 0:
            print("\n❌ All feeds failed to download")
            return 1
        
        print(f"\n✓ Downloaded {successful} of {len(results)} feeds successfully")
        return 0
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Download interrupted by user")
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"\n❌ Unexpected error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
