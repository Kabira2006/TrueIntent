"""Celery task persistence tests use an in-memory stand-in, not PostgreSQL."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from types import SimpleNamespace

import pytest
from billiard.exceptions import SoftTimeLimitExceeded

from app.core.sandbox import SandboxResult
from app.db.models import BrandReference
from app.workers import tasks
from app.workers.celery_app import celery_app


class _ReferenceQuery:
    def __init__(self, references: list[object]) -> None:
        self.references = references

    def filter(self, *criteria: object) -> _ReferenceQuery:
        return self

    def __iter__(self):
        return iter(self.references)


class _Session:
    def __init__(self, job: SimpleNamespace) -> None:
        self.job = job
        self.commits = 0
        self.references: list[object] = []

    def get(self, model: type, job_id: uuid.UUID) -> SimpleNamespace | None:
        return self.job if self.job.id == job_id else None

    def commit(self) -> None:
        self.commits += 1

    def query(self, model: type) -> _ReferenceQuery:
        assert model is BrandReference
        return _ReferenceQuery(self.references)


def _job() -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        status="FAST_PATH_DONE",
        input_payload="https://example.com/path",
        payload_type="URL",
        lexical_indicators={
            "status": "UNAVAILABLE",
            "indicators": [
                {
                    "code": "CHECK_UNAVAILABLE",
                    "severity": "info",
                    "message": "URL spelling checks could not be completed.",
                    "evidence": {"status": "UNAVAILABLE"},
                }
            ],
        },
        transaction_indicators={"status": "NOT_APPLICABLE", "indicators": []},
        sandbox_indicators={"status": "PENDING", "indicators": []},
        final_advisory_status="INCONCLUSIVE",
        signal_vector={"domain_age_days": 45, "is_punycode": 0},
        heuristic_score=0.0,
        error_message=None,
        completed_at=None,
    )


def _install_session(monkeypatch: pytest.MonkeyPatch, job: SimpleNamespace) -> _Session:
    session = _Session(job)

    def session_generator() -> Iterator[_Session]:
        yield session

    monkeypatch.setattr(tasks, "get_sync_session", session_generator)
    return session


def test_successful_sandbox_persists_only_hash_and_keeps_fast_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = _job()
    fast_path_technical = job.lexical_indicators
    session = _install_session(monkeypatch, job)
    session.references = [
        SimpleNamespace(
            brand_name="Example Bank",
            official_domain="example.com",
            phash_signature="0000000000000000",
        )
    ]

    async def scan_page(url: str, *, domain_age_days: int | None = None):
        assert domain_age_days == 45
        return SandboxResult(
            status="NO_INDICATORS",
            indicators=[],
            features={
                "phash": "0000000000000000",
                "final_host": "copycat.test",
            },
        )

    monkeypatch.setattr(tasks, "scan_page", scan_page)
    result = tasks.sandbox_scan.run(str(job.id))

    assert result == {"status": "COMPLETED", "scan_id": str(job.id)}
    assert session.commits == 1
    assert job.lexical_indicators == fast_path_technical
    assert job.sandbox_indicators["features"]["phash"] == "0000000000000000"
    match = job.sandbox_indicators["indicators"][0]
    assert match["code"] == "VISUAL_BRAND_IMPERSONATION"
    assert match["evidence"]["brand"] == "Example Bank"
    assert "image" not in str(job.sandbox_indicators).lower()
    assert job.signal_vector["domain_age_days"] == 45
    assert job.error_message is None
    assert job.completed_at is not None


def test_celery_worker_is_bounded_and_acks_after_execution() -> None:
    assert celery_app.conf.worker_concurrency == 2
    assert celery_app.conf.task_acks_late is True
    assert tasks.sandbox_scan.max_retries == 0
    assert tasks.sandbox_scan.soft_time_limit == 45
    assert tasks.sandbox_scan.time_limit == 60


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (RuntimeError("browser error"), "Sandbox check failed (RuntimeError)."),
        (SoftTimeLimitExceeded(), "Sandbox soft time limit exceeded."),
    ],
)
def test_failed_sandbox_preserves_fast_path_results(
    monkeypatch: pytest.MonkeyPatch,
    exception: Exception,
    expected: str,
) -> None:
    job = _job()
    fast_path_technical = job.lexical_indicators
    session = _install_session(monkeypatch, job)

    async def fail_scan(url: str, *, domain_age_days: int | None = None):
        raise exception

    monkeypatch.setattr(tasks, "scan_page", fail_scan)
    result = tasks.sandbox_scan.run(str(job.id))

    assert result["status"] == "FAILED"
    assert session.commits == 1
    assert job.status == "FAILED"
    assert job.error_message == expected
    assert job.lexical_indicators == fast_path_technical
    assert job.sandbox_indicators["status"] == "UNAVAILABLE"
    assert job.final_advisory_status == "INCONCLUSIVE"
    assert job.completed_at is not None
