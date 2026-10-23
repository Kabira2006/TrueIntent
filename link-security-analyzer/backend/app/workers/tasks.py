"""Synchronous Celery task boundary for async sandbox scanning."""

import asyncio
import logging
import uuid
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

from billiard.exceptions import SoftTimeLimitExceeded

from app.config import get_settings
from app.core.aggregator import AdvisoryPillar, build_report
from app.core.models import Indicator
from app.core.sandbox import (
    SandboxResult,
    match_brand_references,
    scan_page,
)
from app.db.models import BrandReference, ScanJob
from app.db.session import get_sync_session
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)
_UTC = timezone.utc  # noqa: UP017 - local validation runtime is Python 3.10


@celery_app.task(
    bind=True,
    name="app.workers.tasks.sandbox_scan",
    max_retries=0,
    soft_time_limit=get_settings().sandbox_task_soft_time_limit_seconds,
    time_limit=get_settings().sandbox_task_time_limit_seconds,
)
def sandbox_scan(self: Any, scan_id: str) -> dict[str, str]:
    """Run the browser check and preserve the already-saved fast-path report."""
    try:
        job_id = uuid.UUID(scan_id)
    except ValueError:
        logger.error("sandbox task received invalid scan_id=%s", scan_id)
        return {"status": "FAILED", "error": "invalid_scan_id"}

    with closing(get_sync_session()) as session_generator:
        session = next(session_generator)
        job = session.get(ScanJob, job_id)
        if job is None:
            logger.error("sandbox task could not find scan_id=%s", scan_id)
            return {"status": "FAILED", "error": "scan_not_found"}
        if job.status not in {"FAST_PATH_DONE", "PENDING"}:
            return {"status": job.status, "scan_id": scan_id}

        try:
            domain_age = _domain_age(job.signal_vector)
            result = asyncio.run(
                scan_page(job.input_payload, domain_age_days=domain_age)
            )
            references = session.query(BrandReference).filter(
                BrandReference.phash_signature.is_not(None)
            )
            matches = match_brand_references(
                result.features.get("phash"),
                result.features.get("final_host"),
                list(references),
                threshold=get_settings().phash_distance_threshold,
            )
            result = result.model_copy(
                update={"indicators": [*result.indicators, *matches]}
            )
            _store_sandbox_result(job, result)
            if result.status == "UNAVAILABLE":
                _mark_failed(
                    job,
                    "The browser check timed out or could not be completed.",
                )
            else:
                job.status = "COMPLETED"
                job.error_message = None
                job.completed_at = datetime.now(_UTC)
            _recompute_report(job)
        except SoftTimeLimitExceeded:
            _fail_without_losing_fast_path(job, "Sandbox soft time limit exceeded.")
        except TimeoutError:
            _fail_without_losing_fast_path(job, "Sandbox check timed out.")
        except Exception as error:  # noqa: BLE001 - persist failure and retain fast path
            logger.error(
                "sandbox task failed scan_id=%s error_type=%s",
                scan_id,
                type(error).__name__,
            )
            _fail_without_losing_fast_path(
                job, f"Sandbox check failed ({type(error).__name__})."
            )
        session.commit()
        return {"status": job.status, "scan_id": scan_id}


def _store_sandbox_result(job: ScanJob, result: SandboxResult) -> None:
    """Persist the pillar plus only the image fingerprint, never image bytes."""
    pillar_status = (
        "UNAVAILABLE"
        if result.status == "UNAVAILABLE"
        else "FLAGGED"
        if result.indicators
        else "NO_INDICATORS"
    )
    job.sandbox_indicators = {
        "status": pillar_status,
        "indicators": [item.model_dump(mode="json") for item in result.indicators],
        "features": result.features,
    }


def _mark_failed(job: ScanJob, message: str) -> None:
    job.status = "FAILED"
    job.error_message = message
    job.completed_at = datetime.now(_UTC)


def _fail_without_losing_fast_path(job: ScanJob, message: str) -> None:
    job.sandbox_indicators = {
        "status": "UNAVAILABLE",
        "indicators": [
            Indicator(
                code="SANDBOX_UNAVAILABLE",
                severity="info",
                message="The browser check could not be completed.",
                evidence={"status": "UNAVAILABLE"},
            ).model_dump(mode="json")
        ],
        "features": {},
    }
    _mark_failed(job, message)
    _recompute_report(job)


def _recompute_report(job: ScanJob) -> None:
    technical = _stored_pillar(job.lexical_indicators)
    transaction = _stored_pillar(job.transaction_indicators)
    sandbox = _stored_pillar(job.sandbox_indicators)
    report = build_report(
        technical,
        {"status": "AVAILABLE", "indicators": [], "features": {}},
        {"status": "AVAILABLE", "indicators": [], "features": {}},
        transaction if job.payload_type in {"UPI_DEEP_LINK", "QR_TEXT"} else None,
        sandbox,
        payload_type=job.payload_type,
    )
    job.final_advisory_status = report.overall_indicator
    prior_vector = job.signal_vector if isinstance(job.signal_vector, dict) else {}
    job.signal_vector = {**report.signal_vector, **prior_vector}
    job.heuristic_score = report.heuristic_score


def _stored_pillar(value: Any) -> AdvisoryPillar:
    try:
        return AdvisoryPillar.model_validate(
            {"status": value.get("status"), "indicators": value.get("indicators", [])}
        )
    except (AttributeError, TypeError, ValueError):
        return AdvisoryPillar(status="UNAVAILABLE", indicators=[])


def _domain_age(signal_vector: Any) -> int | None:
    if not isinstance(signal_vector, dict):
        return None
    value = signal_vector.get("domain_age_days")
    return value if isinstance(value, int) and value >= 0 else None
