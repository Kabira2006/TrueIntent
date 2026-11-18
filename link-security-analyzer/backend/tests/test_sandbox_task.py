"""Celery task persistence tests use an in-memory stand-in, not PostgreSQL."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from types import SimpleNamespace

import pytest
from app.db.models import BrandReference
from app.sandbox.browser import VisitResult
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


def test_successful_sandbox_persists_metadata_without_screenshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = _job()
    fast_path_technical = job.lexical_indicators
    session = _install_session(monkeypatch, job)

    async def visit(url: str, *, budget_s: float = 15.0):
        assert url == "https://example.com/path"
        return VisitResult(
            final_url="https://example.com/",
            http_status=200,
            title="Example",
            rendered_html='<html><form><input type="password"></form></html>',
            screenshot_png=b"not-persisted",
        )

    monkeypatch.setattr(tasks, "visit", visit)
    result = tasks.run_sandbox.run(str(job.id))

    assert result == {"status": "COMPLETED", "scan_id": str(job.id)}
    assert session.commits == 2
    assert job.lexical_indicators == fast_path_technical
    assert job.sandbox_indicators["features"]["http_status"] == 200
    assert job.sandbox_indicators["features"]["screenshot_retained"] is False
    assert "HAS_PASSWORD_FIELD" in {
        indicator["code"] for indicator in job.sandbox_indicators["indicators"]
    }
    assert job.status == "COMPLETED"
    assert "image" not in str(job.sandbox_indicators).lower()
    assert job.error_message is None
    assert job.completed_at is not None


def test_celery_worker_is_bounded_and_acks_after_execution() -> None:
    assert celery_app.conf.worker_concurrency == 2
    assert celery_app.conf.task_acks_late is True
    assert tasks.run_sandbox.max_retries == 0


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (RuntimeError("browser error"), "Sandbox check failed (RuntimeError)."),
        (TimeoutError(), "Sandbox check timed out."),
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

    async def fail_visit(url: str, *, budget_s: float = 15.0):
        raise exception

    monkeypatch.setattr(tasks, "visit", fail_visit)
    result = tasks.run_sandbox.run(str(job.id))

    assert result["status"] == "complete_partial"
    assert session.commits == 2
    assert job.status == "complete_partial"
    assert job.error_message == expected
    assert job.lexical_indicators == fast_path_technical
    assert job.sandbox_indicators["status"] == "UNAVAILABLE"
    assert job.final_advisory_status == "SOME_INDICATORS_DETECTED"
    assert job.completed_at is not None
