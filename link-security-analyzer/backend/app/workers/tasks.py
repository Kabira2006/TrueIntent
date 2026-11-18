"""Synchronous Celery task boundary for async sandbox scanning."""

import asyncio
import json
import logging
import tempfile
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from billiard.exceptions import SoftTimeLimitExceeded

from app.config import get_settings
from app.core.aggregator import AdvisoryPillar, build_report
from app.db.models import BrandReference, ScanJob
from app.db.session import get_sync_session
from app.sandbox import dom_analyzer, visual
from app.sandbox.browser import visit
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)
_UTC = timezone.utc  # noqa: UP017 - local validation runtime is Python 3.10

# Artifact storage directory (temporary files with TTL)
_ARTIFACTS_DIR = Path(tempfile.gettempdir()) / "trueintent_artifacts"


@celery_app.task(
    bind=True,
    name="app.workers.tasks.run_sandbox",
    max_retries=0,
    soft_time_limit=get_settings().sandbox_task_soft_time_limit_seconds,
    time_limit=get_settings().sandbox_task_time_limit_seconds,
)
def run_sandbox(self: Any, scan_id: str) -> dict[str, str]:
    """Run the browser visit and update scan status through transitions.

    Status transitions:
    - FAST_PATH_DONE -> sandbox_queued (implicit when task is queued)
    - sandbox_queued -> sandbox_running (when task starts)
    - sandbox_running -> complete (success) or complete_partial (failure)
    """
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
        if job.status not in {"FAST_PATH_DONE", "PENDING", "sandbox_queued"}:
            return {"status": job.status, "scan_id": scan_id}

        # Mark as running
        job.status = "sandbox_running"
        session.commit()

        try:
            # Run visit
            result = asyncio.run(visit(job.input_payload, budget_s=15.0))

            # Store compact result
            _store_visit_result(job, result, session)

            # Check for failure conditions
            if result.errors:
                reason = _classify_error(result.errors)
                _mark_complete_partial(job, reason)
            else:
                job.status = "COMPLETED"
                job.error_message = None
                job.completed_at = datetime.now(_UTC)

            _recompute_report(job)

        except SoftTimeLimitExceeded:
            _fail_with_reason(job, "timeout", "Sandbox soft time limit exceeded.")
        except TimeoutError:
            _fail_with_reason(job, "timeout", "Sandbox check timed out.")
        except Exception as error:
            logger.exception(
                "sandbox task failed scan_id=%s error_type=%s",
                scan_id,
                type(error).__name__,
            )
            _fail_with_reason(
                job,
                "browser_crash",
                f"Sandbox check failed ({type(error).__name__}).",
            )

        session.commit()
        return {"status": job.status, "scan_id": scan_id}


def _store_visit_result(job: ScanJob, result: Any, session: Any) -> None:
    """Analyze rendered page content and store compact findings and hashes."""
    indicators: list[dict[str, Any]] = []
    features: dict[str, Any] = {
        "final_url": result.final_url,
        "http_status": result.http_status,
        "title": result.title,
        "contacted_hosts_count": len(result.contacted_hosts),
        "third_party_ratio": result.third_party_ratio,
        "screenshot_retained": False,
        "favicon_retained": False,
        "redirect_count": len(result.redirect_chain),
        "download_attempted": result.download_attempted,
        "blocked_requests_count": len(result.blocked_requests),
        **result.timings,
    }

    if result.rendered_html:
        analysis = dom_analyzer.analyze(
            result.rendered_html,
            job.input_payload,
            result.final_url,
            headers=result.response_headers,
            domain_age_days=_domain_age(job.signal_vector),
            auto_download=result.download_attempted,
            redirect_chain=[
                {"url": hop.url, "status": hop.status}
                for hop in result.redirect_chain
            ],
        )
        indicators.extend(_normalize_signals(analysis.signals))

    if result.screenshot_png:
        hashes = visual.compute_hashes(
            result.screenshot_png,
            result.favicon_bytes,
        )
        features.update(
            {
                key: value
                for key, value in hashes.items()
                if key.endswith("_hex") or key == "favicon_sha256"
            }
        )
        references = [
            {
                "brand_id": ref.brand_id,
                "brand_name": ref.brand_name,
                "official_domains": ref.official_domains,
                "source_url": ref.source_url,
                "phash_hex": ref.phash_hex,
                "dhash_hex": ref.dhash_hex,
                "upper_phash_hex": ref.upper_phash_hex,
                "favicon_sha256": ref.favicon_sha256,
                "favicon_phash_hex": ref.favicon_phash_hex,
            }
            for ref in session.query(BrandReference)
        ]
        parsed = urlsplit(result.final_url)
        hostname = parsed.hostname or ""
        registered_domain = _registered_domain(hostname)
        dom_codes = {indicator["code"] for indicator in indicators}
        visual_result = visual.match_brands(
            hashes,
            references,
            registered_domain,
        )
        indicators.extend(
            _normalize_signal_dicts(
                visual.generate_signals(
                    visual_result,
                    has_credential_fields=bool(
                        dom_codes
                        & {
                            "HAS_PASSWORD_FIELD",
                            "HAS_CARD_FIELDS",
                            "HAS_OTP_PIN_FIELD",
                            "HAS_UPI_ID_FIELD",
                        }
                    ),
                )
            )
        )

    # Add blocked request indicator if any
    if result.blocked_requests:
        indicators.append(
            {
                "code": "NETGUARD_BLOCKED_REQUESTS",
                "severity": "medium",
                "message": f"{len(result.blocked_requests)} requests blocked by netguard",
                "evidence": {
                    "count": len(result.blocked_requests),
                    "samples": result.blocked_requests[:5],
                },
                "points": 10,
            }
        )

    # Add download attempt indicator
    if result.download_attempted:
        indicators.append(
            {
                "code": "DOWNLOAD_ATTEMPTED",
                "severity": "medium",
                "message": "Page attempted to trigger a download",
                "evidence": {},
                "points": 15,
            }
        )

    # Add redirect indicator if many redirects
    if len(result.redirect_chain) > 3:
        indicators.append(
            {
                "code": "EXCESSIVE_REDIRECTS",
                "severity": "low",
                "message": f"Page redirected {len(result.redirect_chain)} times",
                "evidence": {"count": len(result.redirect_chain)},
                "points": 5,
            }
        )

    # Store in sandbox_indicators
    pillar_status = "FLAGGED" if indicators else "NO_INDICATORS"
    if result.errors:
        pillar_status = "UNAVAILABLE"

    job.sandbox_indicators = {
        "status": pillar_status,
        "indicators": indicators,
        "features": features,
    }


def _normalize_signals(signals: list[Any]) -> list[dict[str, Any]]:
    """Convert analyzer signals without retaining page text or nested content."""
    return _normalize_signal_dicts(
        [
            {
                "id": signal.id,
                "severity": signal.severity,
                "explanation": signal.explain,
                "evidence": signal.evidence,
            }
            for signal in signals
        ]
    )


def _normalize_signal_dicts(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for signal in signals:
        evidence = signal.get("evidence", {})
        safe_evidence = {
            key: value
            if isinstance(value, (str, int, float, bool)) or value is None
            else json.dumps(value, ensure_ascii=True)[:500]
            for key, value in evidence.items()
            if key not in {"visible_text_excerpt", "forms", "html"}
        }
        severity = signal.get("severity", "info")
        normalized.append(
            {
                "code": signal.get("id", "SANDBOX_SIGNAL"),
                "severity": "high" if severity == "critical" else severity,
                "message": signal.get("explanation", signal.get("message", "Page indicator detected.")),
                "evidence": safe_evidence,
                "points": signal.get("points", 0),
            }
        )
    return normalized


def _registered_domain(hostname: str) -> str:
    """Return a registrable domain using the bundled suffix data only."""
    import tldextract

    extracted = tldextract.TLDExtract(
        cache_dir=str(_ARTIFACTS_DIR / "suffix_cache"),
        suffix_list_urls=(),
        include_psl_private_domains=True,
    )(hostname)
    return extracted.top_domain_under_public_suffix or hostname


def _classify_error(errors: list[str]) -> str:
    """Classify error list into a specific reason code."""
    error_text = " ".join(errors).lower()
    if "timeout" in error_text:
        return "timeout"
    if "dns" in error_text:
        return "dns"
    if "ssl" in error_text or "certificate" in error_text:
        return "ssl_error"
    if "blocked" in error_text or "netguard" in error_text:
        return "blocked_by_netguard"
    if "browser" in error_text or "playwright" in error_text:
        return "browser_crash"
    return "unknown_error"


def _mark_complete_partial(job: ScanJob, reason: str) -> None:
    """Mark scan as complete_partial with specific reason."""
    job.status = "complete_partial"
    job.error_message = f"Sandbox unavailable: {reason}"
    job.completed_at = datetime.now(_UTC)

    # Add unavailable indicator
    if job.sandbox_indicators is None:
        job.sandbox_indicators = {}
    job.sandbox_indicators["status"] = "UNAVAILABLE"
    if "indicators" not in job.sandbox_indicators:
        job.sandbox_indicators["indicators"] = []
    job.sandbox_indicators["indicators"].append(
        {
            "code": "SANDBOX_UNAVAILABLE",
            "severity": "info",
            "message": f"Browser check unavailable: {reason}",
            "evidence": {"reason": reason},
            "points": 0,
        }
    )


def _fail_with_reason(job: ScanJob, reason: str, message: str) -> None:
    """Mark scan as failed with specific reason and preserve fast-path results."""
    _mark_complete_partial(job, reason)
    job.error_message = message
    _recompute_report(job)


def _recompute_report(job: ScanJob) -> None:
    technical = _stored_pillar(job.lexical_indicators)
    infrastructure = getattr(job, "infrastructure_indicators", None) or {
        "status": "AVAILABLE",
        "indicators": [],
        "features": {},
    }
    feeds = getattr(job, "threat_feed_indicators", None) or {
        "status": "AVAILABLE",
        "indicators": [],
        "features": {},
    }
    transaction = _stored_pillar(job.transaction_indicators)
    sandbox = _stored_pillar(job.sandbox_indicators)
    report = build_report(
        technical,
        infrastructure,
        feeds,
        transaction if job.payload_type in {"UPI_DEEP_LINK", "QR_TEXT"} else None,
        sandbox,
        payload_type=job.payload_type,
    )
    job.final_advisory_status = report.overall_indicator
    prior_vector = job.signal_vector if isinstance(job.signal_vector, dict) else {}
    job.signal_vector = {**prior_vector, **report.signal_vector}
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



@celery_app.task(name="app.workers.tasks.cleanup_old_artifacts")
def cleanup_old_artifacts() -> dict[str, int]:
    """Delete old screenshots and cached results based on retention policy.
    
    Runs periodically via Celery Beat (every 6 hours).
    Returns counts of artifacts deleted.
    """
    settings = get_settings()
    now = datetime.now(_UTC)
    cutoff_timestamp = now.timestamp() - (settings.artifact_ttl_hours * 3600)
    
    # Delete old artifact files (screenshots, favicons, HTML)
    artifacts_deleted = 0
    if _ARTIFACTS_DIR.exists():
        for artifact_file in _ARTIFACTS_DIR.glob("*"):
            try:
                # Files are named with TTL timestamp: {id}_{type}_{ttl}.ext
                parts = artifact_file.stem.split("_")
                if len(parts) >= 3:
                    try:
                        file_ttl = float(parts[-1])
                        if now.timestamp() > file_ttl:
                            artifact_file.unlink()
                            artifacts_deleted += 1
                    except (ValueError, IndexError):
                        # File doesn't follow naming convention, check mtime
                        if artifact_file.stat().st_mtime < cutoff_timestamp:
                            artifact_file.unlink()
                            artifacts_deleted += 1
            except (OSError, FileNotFoundError) as error:
                logger.warning(
                    "Could not delete artifact file=%s error=%s",
                    artifact_file,
                    type(error).__name__,
                )
    
    # Delete old cached scan results from database
    # (scans older than result_cache_ttl_days)
    cache_cutoff = now.timestamp() - (settings.result_cache_ttl_days * 86400)
    cache_cutoff_datetime = datetime.fromtimestamp(cache_cutoff, tz=_UTC)
    
    results_deleted = 0
    with closing(get_sync_session()) as session_generator:
        session = next(session_generator)
        try:
            # Delete old completed scans
            old_scans = session.query(ScanJob).filter(
                ScanJob.completed_at < cache_cutoff_datetime,
                ScanJob.status.in_(["COMPLETED", "complete_partial", "FAILED"])
            ).all()
            
            results_deleted = len(old_scans)
            for scan in old_scans:
                session.delete(scan)
            
            session.commit()
            logger.info(
                "Cleanup completed: artifacts_deleted=%d results_deleted=%d",
                artifacts_deleted,
                results_deleted,
            )
        except Exception as error:
            logger.exception(
                "Cleanup failed: error_type=%s",
                type(error).__name__,
            )
            session.rollback()
    
    return {
        "artifacts_deleted": artifacts_deleted,
        "results_deleted": results_deleted,
    }
