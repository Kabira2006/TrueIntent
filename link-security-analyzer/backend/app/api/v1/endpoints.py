"""Scan submission, polling, and Redis fixed-window rate limiting."""

import logging
import time
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timezone

import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.schemas import (
    AdvisoryReportResponse,
    FastPathSummary,
    ScanAccepted,
    ScanReport,
    ScanRequest,
)
from app.config import get_settings
from app.core.aggregator import AdvisoryPillar
from app.core.models import Indicator
from app.core.service import run_fast_path
from app.db.models import DomainRecord, ScanJob
from app.db.session import get_db
from app.workers.tasks import sandbox_scan

logger = logging.getLogger(__name__)
router = APIRouter()
_UTC = timezone.utc  # noqa: UP017 - local validation runtime is Python 3.10
_RATE_LIMIT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return count
"""


async def get_redis_client() -> AsyncIterator[redis.Redis]:
    """Yield one Redis client per request and close it afterwards."""
    client = redis.from_url(get_settings().redis_url)
    try:
        yield client
    finally:
        try:
            await client.aclose()
        except RedisError as error:
            logger.warning("Redis connection close failed (%s)", type(error).__name__)


async def _enforce_rate_limit(
    request: Request,
    client: redis.Redis,
    *,
    route: str,
    limit: int,
) -> None:
    client_ip = request.client.host if request.client is not None else "unknown"
    now = int(time.time())
    bucket = now // 60
    key = f"rate-limit:{route}:{client_ip}:{bucket}"
    try:
        count = int(await client.eval(_RATE_LIMIT_SCRIPT, 1, key, 60))
    except RedisError as error:
        logger.warning("rate limiter unavailable (%s)", type(error).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The request limit could not be checked.",
        ) from error
    if count > limit:
        retry_after = 60 - (now % 60)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Request limit reached; try again after the indicated delay.",
            headers={"Retry-After": str(retry_after)},
        )


async def _limit_scan(
    request: Request,
    client: redis.Redis = Depends(get_redis_client),  # noqa: B008
) -> None:
    await _enforce_rate_limit(
        request,
        client,
        route="scan",
        limit=get_settings().rate_limit_scan_per_min,
    )


async def _limit_get(
    request: Request,
    client: redis.Redis = Depends(get_redis_client),  # noqa: B008
) -> None:
    await _enforce_rate_limit(
        request,
        client,
        route="get",
        limit=get_settings().rate_limit_get_per_min,
    )


async def _domain_repository(session: AsyncSession, domain: str) -> DomainRecord | None:
    return await session.scalar(
        select(DomainRecord).where(DomainRecord.domain_name == domain)
    )


def enqueue_sandbox(scan_id: uuid.UUID) -> None:
    """Queue the isolated browser task without doing browser work in the API."""
    sandbox_scan.delay(str(scan_id))


@router.post(
    "/scan",
    response_model=ScanAccepted,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(_limit_scan)],
)
async def create_scan(
    body: ScanRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_db),  # noqa: B008
    cache: redis.Redis = Depends(get_redis_client),  # noqa: B008
) -> ScanAccepted:
    """Run fast checks, persist their result, and return a polling location."""
    try:
        fast_result = await run_fast_path(
            body.input,
            redis_client=cache,
            domain_repository=lambda domain: _domain_repository(session, domain),
        )
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(error),
        ) from error

    settings = get_settings()
    should_enqueue_sandbox = (
        fast_result.classification.payload_type == "URL" and settings.sandbox_enabled
    )
    scan_status = "FAST_PATH_DONE" if should_enqueue_sandbox else "COMPLETED"
    scan_id = uuid.uuid4()
    report = fast_result.advisory_report
    job = ScanJob(
        id=scan_id,
        input_payload=fast_result.classification.normalized_payload,
        payload_type=fast_result.classification.payload_type,
        status=scan_status,
        lexical_indicators=report.technical_url_analysis.model_dump(mode="json"),
        infrastructure_indicators={},
        threat_feed_indicators={},
        transaction_indicators=report.transaction_context_analysis.model_dump(
            mode="json"
        ),
        sandbox_indicators=report.visual_brand_analysis.model_dump(mode="json"),
        final_advisory_status=report.overall_indicator,
        signal_vector=report.signal_vector,
        heuristic_score=report.heuristic_score,
        completed_at=None if should_enqueue_sandbox else datetime.now(_UTC),
    )
    session.add(job)
    await session.commit()
    if should_enqueue_sandbox:
        try:
            enqueue_sandbox(scan_id)
        except Exception as error:
            logger.exception(
                "sandbox enqueue failed scan_id=%s error_type=%s",
                scan_id,
                type(error).__name__,
            )
            job.status = "FAILED"
            job.error_message = (
                f"Sandbox task could not be queued ({type(error).__name__})."
            )
            job.sandbox_indicators = AdvisoryPillar(
                status="UNAVAILABLE",
                indicators=[
                    Indicator(
                        code="SANDBOX_UNAVAILABLE",
                        severity="info",
                        message="The browser check could not be queued.",
                        evidence={"status": "UNAVAILABLE"},
                    )
                ],
            ).model_dump(mode="json")
            if job.final_advisory_status != "HIGH_RISK_INDICATORS_DETECTED":
                job.final_advisory_status = "INCONCLUSIVE"
            job.completed_at = datetime.now(_UTC)
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="The browser check could not be queued; the fast-path report was saved.",
            ) from error

    summary = FastPathSummary(
        payload_type=fast_result.classification.payload_type,
        domain=fast_result.domain,
        is_punycode=fast_result.is_punycode,
        shannon_entropy=fast_result.shannon_entropy,
        domain_age_days=fast_result.domain_age_days,
        threat_feed_matches=fast_result.threat_feed_matches,
    )
    poll_url = str(request.url_for("get_scan", scan_id=str(scan_id)))
    response.headers["Location"] = poll_url
    return ScanAccepted(
        scan_id=str(scan_id),
        status=scan_status,
        fast_path_summary=summary,
        poll_url=poll_url,
    )


@router.get(
    "/scan/{scan_id}",
    response_model=ScanReport,
    name="get_scan",
    dependencies=[Depends(_limit_get)],
)
async def get_scan(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> ScanReport:
    """Return the stored status and three advisory pillars."""
    job = await session.scalar(select(ScanJob).where(ScanJob.id == scan_id))
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan was not found.",
        )
    technical = _pillar_from_storage(job.lexical_indicators)
    visual = _pillar_from_storage(job.sandbox_indicators)
    transaction = _pillar_from_storage(job.transaction_indicators)
    return ScanReport(
        scan_id=str(job.id),
        status=job.status,
        overall_indicator=job.final_advisory_status,
        advisory_report=AdvisoryReportResponse(
            technical_url_analysis=technical,
            visual_brand_analysis=visual,
            transaction_context_analysis=transaction,
        ),
    )


def _pillar_from_storage(value: object) -> AdvisoryPillar:
    if not isinstance(value, dict):
        return AdvisoryPillar(status="UNAVAILABLE", indicators=[])
    try:
        return AdvisoryPillar.model_validate(
            {"status": value.get("status"), "indicators": value.get("indicators", [])}
        )
    except (TypeError, ValueError):
        logger.error("stored advisory pillar did not match the API schema")
        return AdvisoryPillar(status="UNAVAILABLE", indicators=[])
