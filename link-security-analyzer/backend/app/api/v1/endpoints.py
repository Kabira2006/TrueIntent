"""Scan submission, polling, and Redis fixed-window rate limiting."""

import asyncio
import logging
import time
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.schemas import (
    AdvisoryReportResponse,
    CoverageOut,
    FastPathSummary,
    ScanAccepted,
    ScanReport,
    ScanRequest,
    ScanVerdict,
)
from app.config import get_settings
from app.core.aggregator import AdvisoryPillar
from app.core.models import Indicator
from app.core.service import run_fast_path
from app.db.models import DomainRecord, ScanJob
from app.db.session import get_db
from app.workers.tasks import run_sandbox

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
    except (RedisError, ConnectionError) as error:
        logger.warning(
            "rate limiter unavailable (%s); failing open", type(error).__name__
        )
        return
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
    run_sandbox.delay(str(scan_id))


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
            job.final_advisory_status = "UNKNOWN"
            job.completed_at = datetime.now(_UTC)
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="The browser check could not be queued; the fast-path report was saved.",
            ) from error

    coverage = CoverageOut(
        completed=sorted({c.group for c in fast_result.checks if c.group}),
        unavailable=[
            {"group": c.group or c.name, "reason": c.reason or "unavailable"}
            for c in fast_result.checks
            if c.status != "ok"
        ],
        level=fast_result.coverage_level,
    )
    verdict = ScanVerdict(
        verdict=fast_result.verdict,
        risk_score=fast_result.risk_score,
        risk_score_note=fast_result.risk_score_note,
        coverage=coverage,
        reasons=sorted({s.id for c in fast_result.checks for s in c.signals if s.id}),
    )
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
        verdict=verdict,
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


_cached_playwright_status: tuple[float, bool] | None = None


async def _check_db_quick() -> bool:
    try:
        from sqlalchemy import text

        from app.db.session import get_async_engine

        async def _run() -> None:
            async with get_async_engine().connect() as conn:
                await conn.execute(text("SELECT 1"))

        await asyncio.wait_for(_run(), timeout=1.5)
        return True
    except Exception:  # noqa: BLE001 - health check must never raise
        return False


async def _check_redis_quick() -> bool:
    try:

        async def _run() -> None:
            client = redis.from_url(get_settings().redis_url)
            try:
                await client.ping()
            finally:
                await client.aclose()

        await asyncio.wait_for(_run(), timeout=1.5)
        return True
    except Exception:  # noqa: BLE001 - health check must never raise
        return False


async def _check_worker_quick() -> bool:
    try:
        from app.workers.celery_app import celery_app

        def _ping() -> bool:
            insp = celery_app.control.inspect(timeout=1.0)
            p = insp.ping() if insp else None
            return bool(p)

        return await asyncio.wait_for(asyncio.to_thread(_ping), timeout=2.0)
    except Exception:  # noqa: BLE001 - health check must never raise
        return False


async def _check_playwright_quick() -> bool:
    global _cached_playwright_status
    now = time.time()
    if _cached_playwright_status is not None:
        cached_time, cached_val = _cached_playwright_status
        if now - cached_time < 60.0:
            return cached_val
    try:
        from playwright.async_api import async_playwright

        async def _run() -> None:
            async with async_playwright() as p:
                b = await p.chromium.launch(headless=True)
                await b.close()

        await asyncio.wait_for(_run(), timeout=5.0)
        _cached_playwright_status = (now, True)
        return True
    except Exception as e:  # noqa: BLE001 - health check must never raise
        logger.info("playwright health check failed (%s)", type(e).__name__)
        _cached_playwright_status = (now, False)
        return False


def _get_git_commit() -> str | None:
    try:
        import subprocess

        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1.0,
        )
        return out.strip()
    except Exception:  # noqa: BLE001 - git commit probe can fail outside git repo
        return None


@router.get("/health", name="health")
async def get_health() -> dict[str, object]:
    """Rich health check reporting db, redis, worker, playwright, and app version."""
    from app.core.reputation import get_feed_status
    from app.db.session import get_async_session
    
    db_ok, redis_ok, worker_ok, playwright_ok = await asyncio.gather(
        _check_db_quick(),
        _check_redis_quick(),
        _check_worker_quick(),
        _check_playwright_quick(),
    )
    settings = get_settings()
    
    # Get local feed status
    reputation_feeds: dict[str, Any] = {}
    try:
        async with get_async_session() as session:
            reputation_feeds = await get_feed_status(session)
    except Exception:  # noqa: BLE001
        reputation_feeds = {"error": "could_not_fetch"}
    
    feeds_status = {
        "google_safe_browsing": "configured"
        if bool(settings.gsb_api_key)
        else "unconfigured",
        "virustotal": "configured" if bool(settings.vt_api_key) else "unconfigured",
        "local_feeds": reputation_feeds,
    }
    return {
        "status": "ok" if (db_ok and redis_ok) else "degraded",
        "app_version": "0.1.0",
        "git_commit": _get_git_commit(),
        "database": db_ok,
        "redis": redis_ok,
        "worker": worker_ok,
        "playwright_launch": playwright_ok,
        "threat_feeds": feeds_status,
    }


@router.get("/api/v1/feeds/status", tags=["health"])
async def get_feeds_status_endpoint() -> dict[str, Any]:
    """Get detailed status of all reputation feeds (Tranco, OpenPhish, URLhaus)."""
    from app.core.reputation import get_feed_status
    from app.db.session import get_async_session
    
    try:
        async with get_async_session() as session:
            feeds = await get_feed_status(session)
            return {"feeds": feeds, "status": "ok"}
    except Exception as exc:  # noqa: BLE001
        return {"feeds": {}, "status": "error", "error": str(exc)}


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
