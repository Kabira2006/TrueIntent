"""Library fast-path tests with mocked checks and Redis."""

import asyncio
import hashlib

import pytest

from app.config import Settings
from app.core.service import (
    FastPathResult,
    InfrastructureBundle,
    _cache_key,
    run_fast_path,
)
from app.core.threat_feeds import FeedLookup, ThreatFeedResult


class _Redis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def get(self, key: str):
        return self.values.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self.values[key] = value
        self.ttls[key] = ttl

    async def aclose(self) -> None:
        return None


def _settings(**kwargs) -> Settings:
    return Settings(_env_file=None, **kwargs)


def _feeds() -> ThreatFeedResult:
    empty = FeedLookup(status="NO_MATCH", indicators=[])
    return ThreatFeedResult(
        google_safe_browsing=empty,
        virustotal=empty,
        indicators=[],
        features={
            "gsb_match_count": 0,
            "vt_malicious_count": 0,
            "vt_total_count": 0,
            "gsb_available": True,
            "vt_available": True,
        },
    )


@pytest.fixture
def mocked_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    async def lexical(payload: str):
        return {
            "status": "AVAILABLE",
            "indicators": [],
            "features": {
                "shannon_entropy": 2.5,
                "subdomain_depth": 1,
                "is_punycode": False,
            },
        }

    async def infrastructure(domain, cache, settings, repository):
        return InfrastructureBundle(
            status="AVAILABLE",
            domain_age_days=300,
            indicators=[],
            features={"domain_age_days": 300},
        )

    async def feeds(payload, cache, settings):
        return _feeds()

    monkeypatch.setattr("app.core.service._run_lexical", lexical)
    monkeypatch.setattr("app.core.service._run_infrastructure", infrastructure)
    monkeypatch.setattr("app.core.service._run_feeds", feeds)


async def test_run_fast_path_returns_report_and_model_features(
    mocked_checks: None,
) -> None:
    result = await run_fast_path(
        " HTTPS://Example.com/path ",
        redis_client=_Redis(),  # type: ignore[arg-type]
        settings=_settings(),
    )
    assert isinstance(result, FastPathResult)
    assert result.classification.payload_type == "URL"
    assert result.domain == "example.com"
    assert result.advisory_report.overall_indicator == "INCONCLUSIVE"
    assert result.advisory_report.signal_vector["domain_age_days"] == 300


async def test_fast_path_cache_is_hashed_and_expires_after_one_hour(
    mocked_checks: None,
) -> None:
    cache = _Redis()
    raw = "https://example.com/path"
    await run_fast_path(raw, redis_client=cache, settings=_settings())  # type: ignore[arg-type]
    expected_digest = hashlib.sha256(raw.encode()).hexdigest()
    assert _cache_key(raw) == f"fast-path:{expected_digest}"
    assert cache.ttls[f"fast-path:{expected_digest}"] == 3600


async def test_fast_path_timeout_degrades_slow_check_to_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def slow_lexical(payload: str):
        await asyncio.sleep(1)

    async def infrastructure(domain, cache, settings, repository):
        return InfrastructureBundle(
            status="AVAILABLE",
            domain_age_days=None,
            indicators=[],
            features={"domain_age_days": -1},
        )

    async def feeds(payload, cache, settings):
        return _feeds()

    monkeypatch.setattr("app.core.service._run_lexical", slow_lexical)
    monkeypatch.setattr("app.core.service._run_infrastructure", infrastructure)
    monkeypatch.setattr("app.core.service._run_feeds", feeds)
    result = await run_fast_path(
        "https://example.com",
        redis_client=_Redis(),  # type: ignore[arg-type]
        settings=_settings(fast_path_budget_seconds=0.01),
    )
    assert result.advisory_report.technical_url_analysis.status == "UNAVAILABLE"
    assert result.advisory_report.overall_indicator == "INCONCLUSIVE"


async def test_failed_check_exception_does_not_fail_the_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failing_lexical(payload: str):
        raise RuntimeError("unexpected analyzer failure")

    async def infrastructure(domain, cache, settings, repository):
        return InfrastructureBundle(
            status="AVAILABLE",
            domain_age_days=30,
            indicators=[],
            features={"domain_age_days": 30},
        )

    async def feeds(payload, cache, settings):
        return _feeds()

    monkeypatch.setattr("app.core.service._run_lexical", failing_lexical)
    monkeypatch.setattr("app.core.service._run_infrastructure", infrastructure)
    monkeypatch.setattr("app.core.service._run_feeds", feeds)
    result = await run_fast_path(
        "https://example.com",
        redis_client=_Redis(),  # type: ignore[arg-type]
        settings=_settings(),
    )
    assert result.advisory_report.technical_url_analysis.status == "UNAVAILABLE"
    assert result.advisory_report.overall_indicator == "INCONCLUSIVE"


async def test_input_classification_and_embedded_upi_routing(
    mocked_checks: None,
) -> None:
    result = await run_fast_path(
        "Payment QR: upi://collect?pa=demo%40oksbi",
        redis_client=_Redis(),  # type: ignore[arg-type]
        settings=_settings(),
    )
    assert result.classification.payload_type == "QR_TEXT"
    assert result.analysis_payload.startswith("upi://collect")
    assert result.advisory_report.transaction_context_analysis.status == "FLAGGED"


async def test_cache_outage_does_not_break_fast_path(
    mocked_checks: None,
) -> None:
    class _BrokenRedis(_Redis):
        async def get(self, key: str):
            raise OSError("cache unavailable")

        async def setex(self, key: str, ttl: int, value: str) -> None:
            raise OSError("cache unavailable")

    result = await run_fast_path(
        "upi://pay?pa=demo%40oksbi",
        redis_client=_BrokenRedis(),  # type: ignore[arg-type]
        settings=_settings(),
    )
    assert result.classification.payload_type == "UPI_DEEP_LINK"
