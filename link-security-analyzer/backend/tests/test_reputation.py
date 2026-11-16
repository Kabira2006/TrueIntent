"""Tests for reputation lookups: Tranco and blocklists.

All tests use small fixture feeds; no network access or real feed downloads.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.core.reputation import (
    SHARED_HOSTING_SUFFIXES,
    _is_shared_hosting,
    _normalize_url_for_matching,
    check_blocklist,
    check_tranco_popularity,
    get_feed_status,
)
from app.db.models import BlocklistEntry, FeedMeta, TrancoRank

# Python 3.9 compatibility
UTC = timezone.utc


@pytest.fixture
def mock_ctx():
    """Mock context for check functions."""
    ctx = AsyncMock()
    ctx.registrable_domain = "example.com"
    ctx.normalized_url = "https://example.com/path"
    ctx.host = "example.com"
    return ctx


# Test URL normalization
@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://Example.COM/Path", "https://example.com/Path"),
        ("http://example.com/path#fragment", "http://example.com/path"),
        ("https://example.com/path?query=1", "https://example.com/path?query=1"),
        ("https://example.com/", "https://example.com"),
        ("https://example.com/path/", "https://example.com/path"),
    ],
)
def test_normalize_url_for_matching(url: str, expected: str) -> None:
    assert _normalize_url_for_matching(url) == expected


# Test shared-hosting detection
@pytest.mark.parametrize(
    ("domain", "is_shared"),
    [
        ("github.io", True),
        ("vercel.app", True),
        ("netlify.app", True),
        ("example.com", False),
        ("google.com", False),
    ],
)
def test_is_shared_hosting(domain: str, is_shared: bool) -> None:
    assert _is_shared_hosting(domain) == is_shared


# Test Tranco popularity check
@pytest.mark.asyncio
async def test_tranco_top_10k_returns_negative_30_points(mock_ctx: AsyncMock) -> None:
    """Top-10K domain returns POPULAR_TOP_10K with -30 points."""
    # Create fake session with TrancoRank
    session = AsyncMock()
    result_mock = AsyncMock()
    tranco_mock = TrancoRank(registrable_domain="example.com", rank=5000)
    result_mock.scalar_one_or_none.return_value = tranco_mock
    session.execute.return_value = result_mock
    
    mock_ctx.db_session = session
    mock_ctx.registrable_domain = "example.com"
    
    result = await check_tranco_popularity(mock_ctx)
    
    assert result.status == "ok"
    assert len(result.signals) == 1
    assert result.signals[0].id == "POPULAR_TOP_10K"
    assert result.signals[0].points == -30
    assert result.signals[0].severity == "info"


@pytest.mark.asyncio
async def test_tranco_top_100k_returns_negative_15_points(mock_ctx: AsyncMock) -> None:
    """Top-100K domain returns POPULAR_TOP_100K with -15 points."""
    session = AsyncMock()
    result_mock = AsyncMock()
    tranco_mock = TrancoRank(registrable_domain="example.com", rank=50000)
    result_mock.scalar_one_or_none.return_value = tranco_mock
    session.execute.return_value = result_mock
    
    mock_ctx.db_session = session
    mock_ctx.registrable_domain = "example.com"
    
    result = await check_tranco_popularity(mock_ctx)
    
    assert result.status == "ok"
    assert len(result.signals) == 1
    assert result.signals[0].id == "POPULAR_TOP_100K"
    assert result.signals[0].points == -15


@pytest.mark.asyncio
async def test_tranco_top_1m_returns_negative_5_points(mock_ctx: AsyncMock) -> None:
    """Top-1M domain returns POPULAR_TOP_1M with -5 points."""
    session = AsyncMock()
    result_mock = AsyncMock()
    tranco_mock = TrancoRank(registrable_domain="example.com", rank=500000)
    result_mock.scalar_one_or_none.return_value = tranco_mock
    session.execute.return_value = result_mock
    
    mock_ctx.db_session = session
    mock_ctx.registrable_domain = "example.com"
    
    result = await check_tranco_popularity(mock_ctx)
    
    assert result.status == "ok"
    assert len(result.signals) == 1
    assert result.signals[0].id == "POPULAR_TOP_1M"
    assert result.signals[0].points == -5


@pytest.mark.asyncio
async def test_tranco_not_ranked_returns_no_signals(mock_ctx: AsyncMock) -> None:
    """Domain not in Tranco returns no signals."""
    session = AsyncMock()
    result_mock = AsyncMock()
    result_mock.scalar_one_or_none.return_value = None
    session.execute.return_value = result_mock
    
    mock_ctx.db_session = session
    mock_ctx.registrable_domain = "unknown-domain.xyz"
    
    result = await check_tranco_popularity(mock_ctx)
    
    assert result.status == "ok"
    assert len(result.signals) == 0
    assert result.detail["rank"] is None


@pytest.mark.asyncio
async def test_tranco_shared_hosting_gets_no_popularity_credit(mock_ctx: AsyncMock) -> None:
    """Shared-hosting domain never gets popularity credit."""
    session = AsyncMock()
    mock_ctx.db_session = session
    mock_ctx.registrable_domain = "github.io"
    
    result = await check_tranco_popularity(mock_ctx)
    
    assert result.status == "ok"
    assert len(result.signals) == 0
    assert result.detail.get("shared_hosting") is True
    # Session should not be queried
    session.execute.assert_not_called()


# Test blocklist lookups
@pytest.mark.asyncio
async def test_blocklist_exact_url_match_returns_critical(mock_ctx: AsyncMock) -> None:
    """Exact URL match returns BLOCKLIST_URL_HIT with critical severity."""
    session = AsyncMock()
    
    # Setup two execute calls: first for URL match, second not needed
    url_result = AsyncMock()
    blocklist_entry = BlocklistEntry(
        url_norm="https://example.com/path",
        registrable_domain="example.com",
        source="openphish",
        threat_type="phishing",
        first_seen=datetime.now(UTC),
        fetched_at=datetime.now(UTC),
    )
    url_result.scalar_one_or_none.return_value = blocklist_entry
    session.execute.return_value = url_result
    
    mock_ctx.db_session = session
    mock_ctx.normalized_url = "https://example.com/path"
    mock_ctx.registrable_domain = "example.com"
    mock_ctx.host = "example.com"
    
    result = await check_blocklist(mock_ctx)
    
    assert result.status == "ok"
    assert len(result.signals) == 1
    assert result.signals[0].id == "BLOCKLIST_URL_HIT"
    assert result.signals[0].points == 100
    assert result.signals[0].severity == "critical"
    assert result.signals[0].evidence["source"] == "openphish"


@pytest.mark.asyncio
async def test_blocklist_domain_match_returns_high(mock_ctx: AsyncMock) -> None:
    """Domain match returns BLOCKLIST_DOMAIN_HIT with high severity."""
    session = AsyncMock()
    
    # First call: no URL match
    url_result = AsyncMock()
    url_result.scalar_one_or_none.return_value = None
    
    # Second call: domain match
    domain_result = AsyncMock()
    blocklist_entry = BlocklistEntry(
        url_norm="https://badsite.com/other",
        registrable_domain="badsite.com",
        source="urlhaus",
        threat_type="malware",
        first_seen=datetime.now(UTC),
        fetched_at=datetime.now(UTC),
    )
    domain_result.scalar_one_or_none.return_value = blocklist_entry
    
    session.execute.side_effect = [url_result, domain_result]
    
    mock_ctx.db_session = session
    mock_ctx.normalized_url = "https://badsite.com/newpath"
    mock_ctx.registrable_domain = "badsite.com"
    mock_ctx.host = "badsite.com"
    
    result = await check_blocklist(mock_ctx)
    
    assert result.status == "ok"
    assert len(result.signals) == 1
    assert result.signals[0].id == "BLOCKLIST_DOMAIN_HIT"
    assert result.signals[0].points == 50
    assert result.signals[0].severity == "high"


@pytest.mark.asyncio
async def test_blocklist_no_match_returns_no_signals(mock_ctx: AsyncMock) -> None:
    """No blocklist match returns no signals."""
    session = AsyncMock()
    
    # Both lookups return None
    result_mock = AsyncMock()
    result_mock.scalar_one_or_none.return_value = None
    session.execute.return_value = result_mock
    
    mock_ctx.db_session = session
    mock_ctx.normalized_url = "https://safe-site.com/path"
    mock_ctx.registrable_domain = "safe-site.com"
    mock_ctx.host = "safe-site.com"
    
    result = await check_blocklist(mock_ctx)
    
    assert result.status == "ok"
    assert len(result.signals) == 0
    assert result.detail["match_type"] == "none"


@pytest.mark.asyncio
async def test_blocklist_shared_hosting_matches_full_host_only(mock_ctx: AsyncMock) -> None:
    """Shared-hosting domains match full host, not registrable domain."""
    session = AsyncMock()
    
    # No URL match
    url_result = AsyncMock()
    url_result.scalar_one_or_none.return_value = None
    
    # Domain lookup should use full host (malicious.github.io), not github.io
    domain_result = AsyncMock()
    blocklist_entry = BlocklistEntry(
        url_norm="https://malicious.github.io/phish",
        registrable_domain="malicious.github.io",
        source="openphish",
        threat_type="phishing",
        first_seen=datetime.now(UTC),
        fetched_at=datetime.now(UTC),
    )
    domain_result.scalar_one_or_none.return_value = blocklist_entry
    
    session.execute.side_effect = [url_result, domain_result]
    
    mock_ctx.db_session = session
    mock_ctx.normalized_url = "https://malicious.github.io/phish"
    mock_ctx.registrable_domain = "github.io"  # Platform domain
    mock_ctx.host = "malicious.github.io"  # Full host
    
    result = await check_blocklist(mock_ctx)
    
    assert result.status == "ok"
    assert len(result.signals) == 1
    assert result.signals[0].id == "BLOCKLIST_DOMAIN_HIT"
    assert result.detail["shared_hosting"] is True


# Test feed status
@pytest.mark.asyncio
async def test_feed_status_reports_age_and_freshness() -> None:
    """Feed status correctly computes age and stale flag."""
    session = AsyncMock()
    
    now = datetime.now(UTC)
    fresh_feed = FeedMeta(
        source="tranco",
        fetched_at=now - timedelta(hours=12),
        row_count=1000000,
        license_note="Test license",
    )
    stale_feed = FeedMeta(
        source="openphish",
        fetched_at=now - timedelta(hours=50),
        row_count=5000,
        license_note="Test license",
    )
    
    result_mock = AsyncMock()
    result_mock.scalars.return_value.all.return_value = [fresh_feed, stale_feed]
    session.execute.return_value = result_mock
    
    status = await get_feed_status(session)
    
    assert "tranco" in status
    assert status["tranco"]["row_count"] == 1000000
    assert status["tranco"]["age_hours"] == pytest.approx(12, abs=0.1)
    assert status["tranco"]["stale"] is False
    
    assert "openphish" in status
    assert status["openphish"]["row_count"] == 5000
    assert status["openphish"]["age_hours"] == pytest.approx(50, abs=0.1)
    assert status["openphish"]["stale"] is True


@pytest.mark.asyncio
async def test_feed_status_with_empty_database() -> None:
    """Empty feed database returns empty status."""
    session = AsyncMock()
    result_mock = AsyncMock()
    result_mock.scalars.return_value.all.return_value = []
    session.execute.return_value = result_mock
    
    status = await get_feed_status(session)
    
    assert status == {}
