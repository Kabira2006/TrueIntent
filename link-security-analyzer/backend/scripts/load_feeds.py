#!/usr/bin/env python3
"""Load downloaded reputation feeds into database tables.

Reads from data/raw/ and loads into tranco_rank and blocklist_entries tables.
Idempotent: can be run multiple times; uses UPSERT/merge logic.
"""

from __future__ import annotations

import csv
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import tldextract
from sqlalchemy import delete, text

from app.db.models import BlocklistEntry, TrancoRank
from app.db.session import get_sync_session

# Python 3.9 compatibility
UTC = timezone.utc

DATA_RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
_SUFFIX_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


def _normalize_url(url: str) -> str:
    """Normalize URL for storage: lowercase host, strip fragment."""
    parsed = urlsplit(url)
    normalized = f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    if normalized.endswith("/") and "?" not in normalized:
        normalized = normalized.rstrip("/")
    return normalized


def _registrable_domain(url: str) -> str:
    """Extract registrable domain from URL."""
    parsed = urlsplit(url)
    host = parsed.netloc.split(":")[0]  # Strip port
    extracted = _SUFFIX_EXTRACTOR(host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return host.lower()


def load_tranco(session: any) -> int:
    """Load Tranco top-1M list into tranco_rank table."""
    print("Loading Tranco list...")
    
    # Find most recent Tranco file
    tranco_files = sorted(DATA_RAW_DIR.glob("tranco_*.csv"), reverse=True)
    if not tranco_files:
        print("  ⚠️  No Tranco file found in data/raw/")
        return 0
    
    tranco_file = tranco_files[0]
    print(f"  Reading {tranco_file.name}...")
    
    # Delete existing data
    session.execute(delete(TrancoRank))
    session.commit()
    
    # Load new data (CSV format: rank,domain)
    rows = []
    with tranco_file.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for rank_str, domain in reader:
            try:
                rank = int(rank_str)
                rows.append({"registrable_domain": domain.lower(), "rank": rank})
            except ValueError:
                continue
    
    # Bulk insert
    if rows:
        session.execute(
            text("""
                INSERT INTO tranco_rank (registrable_domain, rank, updated_at)
                VALUES (:registrable_domain, :rank, NOW())
                ON CONFLICT (registrable_domain) DO UPDATE
                SET rank = EXCLUDED.rank, updated_at = NOW()
            """),
            rows,
        )
        session.commit()
    
    print(f"  ✓ Loaded {len(rows):,} domains")
    return len(rows)


def load_openphish(session: any) -> int:
    """Load OpenPhish URLs into blocklist_entries table."""
    print("Loading OpenPhish feed...")
    
    # Find most recent OpenPhish file
    openphish_files = sorted(DATA_RAW_DIR.glob("openphish_*.txt"), reverse=True)
    if not openphish_files:
        print("  ⚠️  No OpenPhish file found in data/raw/")
        return 0
    
    openphish_file = openphish_files[0]
    print(f"  Reading {openphish_file.name}...")
    
    # Read URLs
    urls = []
    with openphish_file.open("r", encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if url and url.startswith("http"):
                urls.append(url)
    
    # Delete old OpenPhish entries
    session.execute(delete(BlocklistEntry).where(BlocklistEntry.source == "openphish"))
    session.commit()
    
    # Bulk insert
    now = datetime.now(UTC)
    rows = []
    for url in urls:
        try:
            url_norm = _normalize_url(url)
            domain = _registrable_domain(url)
            rows.append({
                "url_norm": url_norm,
                "registrable_domain": domain,
                "source": "openphish",
                "threat_type": "phishing",
                "first_seen": now,
                "fetched_at": now,
            })
        except Exception:  # noqa: BLE001
            continue
    
    if rows:
        session.execute(
            text("""
                INSERT INTO blocklist_entries 
                (url_norm, registrable_domain, source, threat_type, first_seen, fetched_at, updated_at)
                VALUES (:url_norm, :registrable_domain, :source, :threat_type, :first_seen, :fetched_at, NOW())
            """),
            rows,
        )
        session.commit()
    
    print(f"  ✓ Loaded {len(rows):,} phishing URLs")
    return len(rows)


def load_urlhaus(session: any) -> int:
    """Load URLhaus malware URLs into blocklist_entries table."""
    print("Loading URLhaus feed...")
    
    # Find most recent URLhaus file
    urlhaus_files = sorted(DATA_RAW_DIR.glob("urlhaus_*.csv"), reverse=True)
    if not urlhaus_files:
        print("  ⚠️  No URLhaus file found in data/raw/")
        return 0
    
    urlhaus_file = urlhaus_files[0]
    print(f"  Reading {urlhaus_file.name}...")
    
    # Delete old URLhaus entries
    session.execute(delete(BlocklistEntry).where(BlocklistEntry.source == "urlhaus"))
    session.commit()
    
    # Read CSV (skip comment lines starting with #)
    urls = []
    with urlhaus_file.open("r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split(",")
            if len(parts) >= 3:
                url = parts[2].strip('"')
                threat_type = parts[4].strip('"') if len(parts) > 4 else "malware"
                urls.append((url, threat_type))
    
    # Bulk insert
    now = datetime.now(UTC)
    rows = []
    for url, threat_type in urls:
        try:
            url_norm = _normalize_url(url)
            domain = _registrable_domain(url)
            rows.append({
                "url_norm": url_norm,
                "registrable_domain": domain,
                "source": "urlhaus",
                "threat_type": threat_type,
                "first_seen": now,
                "fetched_at": now,
            })
        except Exception:  # noqa: BLE001
            continue
    
    if rows:
        session.execute(
            text("""
                INSERT INTO blocklist_entries 
                (url_norm, registrable_domain, source, threat_type, first_seen, fetched_at, updated_at)
                VALUES (:url_norm, :registrable_domain, :source, :threat_type, :first_seen, :fetched_at, NOW())
            """),
            rows,
        )
        session.commit()
    
    print(f"  ✓ Loaded {len(rows):,} malware URLs")
    return len(rows)


def main() -> int:
    """Entry point."""
    print("\n🔄 Loading reputation feeds into database...\n")
    
    try:
        with next(get_sync_session()) as session:
            tranco_count = load_tranco(session)
            openphish_count = load_openphish(session)
            urlhaus_count = load_urlhaus(session)
        
        print("\n📊 Summary:")
        print(f"  Tranco:    {tranco_count:,} domains")
        print(f"  OpenPhish: {openphish_count:,} URLs")
        print(f"  URLhaus:   {urlhaus_count:,} URLs")
        print(f"\n✓ Successfully loaded {tranco_count + openphish_count + urlhaus_count:,} total entries")
        
        return 0
    
    except Exception as exc:
        print(f"\n❌ Error loading feeds: {exc}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
