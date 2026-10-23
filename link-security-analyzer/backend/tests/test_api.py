"""FastAPI scan routes with fake SQL and Redis dependencies."""

import uuid
from collections.abc import AsyncIterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import endpoints
from app.config import Settings
from app.core.aggregator import build_report
from app.core.models import Indicator, InputClassification
from app.core.service import FastPathResult
from app.core.threat_feeds import FeedLookup, ThreatFeedResult
from app.db.models import ScanJob
from app.db.session import get_db
from app.main import app


class _Redis:
    def __init__(self) -> None:
        self.values: dict[str, int] = {}

    async def eval(self, script: str, numkeys: int, key: str, ttl: int) -> int:
        self.values[key] = self.values.get(key, 0) + 1
        return self.values[key]

    async def aclose(self) -> None:
        return None


class _Session:
    def __init__(self) -> None:
        self.jobs: dict[uuid.UUID, ScanJob] = {}
        self.added: list[ScanJob] = []

    def add(self, job: ScanJob) -> None:
        self.added.append(job)
        self.jobs[job.id] = job

    async def commit(self) -> None:
        return None

    async def scalar(self, statement):
        scan_id = statement.compile().params.get("id_1")
        return self.jobs.get(scan_id)


def _settings(**kwargs) -> Settings:
    values = {"rate_limit_scan_per_min": 100, "rate_limit_get_per_min": 100}
    values.update(kwargs)
    return Settings(_env_file=None, **values)


def _sample_fast_result(payload_type: str = "URL") -> FastPathResult:
    empty = FeedLookup(status="NO_MATCH", indicators=[])
    feeds = ThreatFeedResult(
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
    report = build_report(
        {
            "status": "UNAVAILABLE",
            "indicators": [
                Indicator(
                    code="CHECK_UNAVAILABLE",
                    severity="info",
                    message="URL spelling checks could not be completed.",
                    evidence={"status": "UNAVAILABLE"},
                )
            ],
            "features": {"shannon_entropy": 2.75, "is_punycode": False},
        },
        {
            "status": "AVAILABLE",
            "indicators": [],
            "features": {"domain_age_days": 200},
        },
        feeds,
        None,
        None,
        payload_type=payload_type,
    )
    payload = (
        "upi://pay?pa=demo%40oksbi"
        if payload_type == "UPI_DEEP_LINK"
        else "https://example.com/path"
    )
    return FastPathResult(
        classification=InputClassification(
            payload_type=payload_type,  # type: ignore[arg-type]
            normalized_payload=payload,
            recognized=True,
        ),
        analysis_payload=payload,
        domain="example.com" if payload_type == "URL" else None,
        is_punycode=False,
        shannon_entropy=2.75,
        domain_age_days=200 if payload_type == "URL" else None,
        threat_feed_matches=0,
        advisory_report=report,
    )


@pytest.fixture
def api_dependencies(monkeypatch: pytest.MonkeyPatch):
    session = _Session()
    cache = _Redis()

    async def override_db() -> AsyncIterator[AsyncSession]:
        yield session  # type: ignore[misc]

    async def override_redis() -> AsyncIterator:
        yield cache

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[endpoints.get_redis_client] = override_redis
    monkeypatch.setattr(endpoints, "get_settings", lambda: _settings())
    with TestClient(app) as client:
        yield client, session, cache
    app.dependency_overrides.clear()


def test_post_scan_persists_fast_result_and_returns_202(
    api_dependencies, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session, _ = api_dependencies
    monkeypatch.setattr(
        endpoints, "run_fast_path", _result_runner(_sample_fast_result())
    )
    enqueued: list[uuid.UUID] = []
    monkeypatch.setattr(endpoints, "enqueue_sandbox", enqueued.append)

    response = client.post("/api/v1/scan", json={"input": "https://example.com/path"})

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "FAST_PATH_DONE"
    assert body["fast_path_summary"] == {
        "payload_type": "URL",
        "domain": "example.com",
        "is_punycode": False,
        "shannon_entropy": 2.75,
        "domain_age_days": 200,
        "threat_feed_matches": 0,
    }
    assert body["poll_url"].endswith(f"/api/v1/scan/{body['scan_id']}")
    assert response.headers["location"] == body["poll_url"]
    assert len(session.added) == 1
    assert session.added[0].status == "FAST_PATH_DONE"
    assert enqueued == [uuid.UUID(body["scan_id"])]


def test_enqueue_sandbox_dispatches_celery_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = uuid.uuid4()
    queued: list[str] = []
    monkeypatch.setattr(endpoints.sandbox_scan, "delay", queued.append)

    endpoints.enqueue_sandbox(scan_id)

    assert queued == [str(scan_id)]


def test_queue_failure_marks_saved_scan_failed(
    api_dependencies, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session, _ = api_dependencies
    monkeypatch.setattr(
        endpoints, "run_fast_path", _result_runner(_sample_fast_result())
    )

    def fail_enqueue(scan_id: uuid.UUID) -> None:
        raise OSError("queue unavailable")

    monkeypatch.setattr(endpoints, "enqueue_sandbox", fail_enqueue)
    response = client.post("/api/v1/scan", json={"input": "https://example.com/path"})

    assert response.status_code == 503
    job = session.added[0]
    assert job.status == "FAILED"
    assert job.completed_at is not None
    assert job.sandbox_indicators["status"] == "UNAVAILABLE"
    assert job.sandbox_indicators["indicators"][0]["code"] == "SANDBOX_UNAVAILABLE"
    assert job.final_advisory_status == "INCONCLUSIVE"


def test_get_scan_returns_persisted_three_pillar_report(
    api_dependencies, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _, _ = api_dependencies
    monkeypatch.setattr(
        endpoints, "run_fast_path", _result_runner(_sample_fast_result())
    )
    monkeypatch.setattr(endpoints, "enqueue_sandbox", lambda scan_id: None)
    created = client.post("/api/v1/scan", json={"input": "https://example.com/path"})
    scan_id = created.json()["scan_id"]

    response = client.get(f"/api/v1/scan/{scan_id}")

    assert response.status_code == 200
    report = response.json()
    assert report["scan_id"] == scan_id
    assert report["status"] == "FAST_PATH_DONE"
    assert (
        report["advisory_report"]["technical_url_analysis"]["status"] == "UNAVAILABLE"
    )
    assert report["advisory_report"]["visual_brand_analysis"]["status"] == "PENDING"
    assert (
        report["advisory_report"]["transaction_context_analysis"]["status"]
        == "NOT_APPLICABLE"
    )
    assert report["overall_indicator"] == "INCONCLUSIVE"


def test_non_url_scan_completes_without_sandbox(
    api_dependencies, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session, _ = api_dependencies
    monkeypatch.setattr(
        endpoints,
        "get_settings",
        lambda: _settings(sandbox_enabled=True),
    )
    monkeypatch.setattr(
        endpoints,
        "run_fast_path",
        _result_runner(_sample_fast_result("UPI_DEEP_LINK")),
    )

    response = client.post("/api/v1/scan", json={"input": "upi://pay?pa=demo%40oksbi"})

    assert response.status_code == 202
    assert response.json()["status"] == "COMPLETED"
    assert session.added[0].completed_at is not None


@pytest.mark.parametrize(
    "payload", [{"input": ""}, {"input": "x" * 2049}, {"input": "x", "extra": True}]
)
def test_post_scan_validates_request(payload: dict, api_dependencies) -> None:
    client, _, _ = api_dependencies
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 422


def test_get_scan_rejects_invalid_uuid_and_returns_404_for_missing(
    api_dependencies,
) -> None:
    client, _, _ = api_dependencies
    assert client.get("/api/v1/scan/not-a-uuid").status_code == 422
    assert client.get(f"/api/v1/scan/{uuid.uuid4()}").status_code == 404


def test_rate_limit_returns_429_and_retry_after_header(
    api_dependencies, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _, _ = api_dependencies
    monkeypatch.setattr(
        endpoints,
        "get_settings",
        lambda: _settings(rate_limit_scan_per_min=0),
    )
    response = client.post("/api/v1/scan", json={"input": "https://example.com"})
    assert response.status_code == 429
    assert 1 <= int(response.headers["retry-after"]) <= 60


def test_get_rate_limit_returns_429(
    api_dependencies, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _, _ = api_dependencies
    monkeypatch.setattr(
        endpoints, "run_fast_path", _result_runner(_sample_fast_result())
    )
    monkeypatch.setattr(endpoints, "enqueue_sandbox", lambda scan_id: None)
    created = client.post("/api/v1/scan", json={"input": "https://example.com/path"})
    scan_id = created.json()["scan_id"]
    monkeypatch.setattr(
        endpoints,
        "get_settings",
        lambda: _settings(rate_limit_get_per_min=0),
    )

    response = client.get(f"/api/v1/scan/{scan_id}")

    assert response.status_code == 429
    assert 1 <= int(response.headers["retry-after"]) <= 60


def _result_runner(value):
    async def run(*args, **kwargs):
        return value

    return run
