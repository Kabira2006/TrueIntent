"""Reputation lookups: popularity (Tranco) and blocklists (OpenPhish, URLhaus).

All lookups are offline against local database tables populated by
scripts/download_feeds.py. Each check is wrapped as a runner check with
group "reputation" and 1-second timeout.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.runner import CheckResult, Signal, check
from app.db.models import BlocklistEntry, FeedMeta, TrancoRank

# Python 3.9 compatibility
UTC = timezone.utc

# Shared-hosting suffixes: registrable domains under these are platform names,
# not individual sites. For these, match only the full host, never the registrable domain.
SHARED_HOSTING_SUFFIXES = frozenset(
    {
        "github.io",
        "pages.github.io",
        "gitlab.io",
        "vercel.app",
        "netlify.app",
        "pages.dev",
        "cloudflare-pages.dev",
        "web.app",
        "firebaseapp.com",
        "herokuapp.com",
        "azurewebsites.net",
        "blogspot.com",
        "blogspot.in",
        "wordpress.com",
        "wixsite.com",
        "weebly.com",
        "tumblr.com",
        "github.io",
    }
)


def _normalize_url_for_matching(url: str) -> str:
    """Normalize URL for blocklist matching: lowercase host, strip fragment."""
    parsed = urlsplit(url)
    # Lowercase host, keep path and query, strip fragment
    normalized = f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    # Strip trailing slash from path-only URLs
    if normalized.endswith("/") and "?" not in normalized:
        normalized = normalized.rstrip("/")
    return normalized


def _is_shared_hosting(registrable_domain: str) -> bool:
    """True if registrable_domain is a shared-hosting platform."""
    return registrable_domain.lower() in SHARED_HOSTING_SUFFIXES


@check(name="tranco_popularity", timeout_s=1.0, group="reputation")
async def check_tranco_popularity(ctx: Any) -> CheckResult:
    """Check Tranco top-1M rank for the registrable domain.
    
    Returns popularity signals: POPULAR_TOP_10K (-30), POPULAR_TOP_100K (-15),
    POPULAR_TOP_1M (-5). Shared-hosting domains are never given popularity credit.
    """
    registrable_domain: str | None = getattr(ctx, "registrable_domain", None)
    session: AsyncSession | None = getattr(ctx, "db_session", None)
    
    if not registrable_domain or not session:
        return CheckResult(
            name="tranco_popularity",
            status="skipped",
            reason="no_domain_or_session",
        )
    
    # Shared-hosting domains never get popularity credit
    if _is_shared_hosting(registrable_domain):
        return CheckResult(
            name="tranco_popularity",
            status="ok",
            signals=[],
            detail={"shared_hosting": True},
        )
    
    # Look up rank
    stmt = select(TrancoRank).where(TrancoRank.registrable_domain == registrable_domain.lower())
    result = await session.execute(stmt)
    tranco = result.scalar_one_or_none()
    
    if not tranco:
        return CheckResult(
            name="tranco_popularity",
            status="ok",
            signals=[],
            detail={"rank": None},
        )
    
    rank = tranco.rank
    signals: list[Signal] = []
    
    if rank <= 10_000:
        signals.append(
            Signal(
                id="POPULAR_TOP_10K",
                points=-30,
                severity="info",
                explain=f"Domain ranks #{rank:,} in Tranco top 10K; highly popular",
                evidence={"rank": rank, "bucket": "top_10k"},
            )
        )
    elif rank <= 100_000:
        signals.append(
            Signal(
                id="POPULAR_TOP_100K",
                points=-15,
                severity="info",
                explain=f"Domain ranks #{rank:,} in Tranco top 100K; popular",
                evidence={"rank": rank, "bucket": "top_100k"},
            )
        )
    elif rank <= 1_000_000:
        signals.append(
            Signal(
                id="POPULAR_TOP_1M",
                points=-5,
                severity="info",
                explain=f"Domain ranks #{rank:,} in Tranco top 1M",
                evidence={"rank": rank, "bucket": "top_1m"},
            )
        )
    
    return CheckResult(
        name="tranco_popularity",
        status="ok",
        signals=signals,
        detail={"rank": rank},
    )


@check(name="blocklist_lookup", timeout_s=1.0, group="reputation")
async def check_blocklist(ctx: Any) -> CheckResult:
    """Check if URL or domain appears in phishing/malware blocklists.
    
    Returns BLOCKLIST_URL_HIT (critical, exact URL match) or BLOCKLIST_DOMAIN_HIT
    (high, registrable domain match). For shared-hosting domains, only matches full host.
    """
    url: str | None = getattr(ctx, "normalized_url", None)
    registrable_domain: str | None = getattr(ctx, "registrable_domain", None)
    full_host: str | None = getattr(ctx, "host", None)
    session: AsyncSession | None = getattr(ctx, "db_session", None)
    
    if not url or not session:
        return CheckResult(
            name="blocklist_lookup",
            status="skipped",
            reason="no_url_or_session",
        )
    
    # Normalize URL for matching
    url_norm = _normalize_url_for_matching(url)
    
    # Check for exact URL match
    stmt_url = select(BlocklistEntry).where(BlocklistEntry.url_norm == url_norm).limit(1)
    result_url = await session.execute(stmt_url)
    url_match = result_url.scalar_one_or_none()
    
    if url_match:
        return CheckResult(
            name="blocklist_lookup",
            status="ok",
            signals=[
                Signal(
                    id="BLOCKLIST_URL_HIT",
                    points=100,  # Critical - forces DANGEROUS
                    severity="critical",
                    explain=f"Exact URL match in {url_match.source} blocklist",
                    evidence={
                        "source": url_match.source,
                        "threat_type": url_match.threat_type,
                        "first_seen": url_match.first_seen.isoformat() if url_match.first_seen else None,
                    },
                )
            ],
            detail={"match_type": "url", "source": url_match.source},
        )
    
    # Check domain match (but use full host for shared-hosting)
    if registrable_domain:
        is_shared = _is_shared_hosting(registrable_domain)
        match_target = full_host if is_shared else registrable_domain
        
        if match_target:
            stmt_domain = (
                select(BlocklistEntry)
                .where(BlocklistEntry.registrable_domain == match_target.lower())
                .limit(1)
            )
            result_domain = await session.execute(stmt_domain)
            domain_match = result_domain.scalar_one_or_none()
            
            if domain_match:
                return CheckResult(
                    name="blocklist_lookup",
                    status="ok",
                    signals=[
                        Signal(
                            id="BLOCKLIST_DOMAIN_HIT",
                            points=50,
                            severity="high",
                            explain=f"Domain appears in {domain_match.source} blocklist",
                            evidence={
                                "source": domain_match.source,
                                "threat_type": domain_match.threat_type,
                                "matched_domain": match_target,
                                "shared_hosting": is_shared,
                            },
                        )
                    ],
                    detail={
                        "match_type": "domain",
                        "source": domain_match.source,
                        "shared_hosting": is_shared,
                    },
                )
    
    # No match
    return CheckResult(
        name="blocklist_lookup",
        status="ok",
        signals=[],
        detail={"match_type": "none"},
    )


async def get_feed_status(session: AsyncSession) -> dict[str, Any]:
    """Get status of all reputation feeds for health/status endpoints."""
    stmt = select(FeedMeta)
    result = await session.execute(stmt)
    feeds = result.scalars().all()
    
    now = datetime.now(UTC)
    status: dict[str, Any] = {}
    
    for feed in feeds:
        age_hours = (now - feed.fetched_at).total_seconds() / 3600
        is_stale = age_hours > 48
        
        status[feed.source] = {
            "row_count": feed.row_count,
            "fetched_at": feed.fetched_at.isoformat(),
            "age_hours": round(age_hours, 1),
            "stale": is_stale,
            "license": feed.license_note,
        }
    
    return status
