"""Library entry point for bounded, cached fast-path scans."""

import asyncio
import hashlib
import importlib
import inspect
import logging
import math
import re
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Literal, TypeVar
from urllib.parse import urlsplit

import redis.asyncio as redis
from pydantic import BaseModel, ConfigDict
from redis.exceptions import RedisError

from app.config import Settings, get_settings
from app.core.aggregator import AdvisoryReport, build_report
from app.core.brands import BrandCatalog, load_brands
from app.core.infrastructure import DnsInfo, DomainInfo, get_domain_info, resolve_dns
from app.core.models import Indicator, InputClassification
from app.core.router import RouteResult, classify_and_route
from app.core.runner import CheckGroup, CheckResult, CheckSpec, run_checks
from app.core.threat_feeds import FeedLookup, ThreatFeedResult, check_threat_feeds
from app.core.upi import UpiResult, analyze_upi
from app.core.verdict import compute_coverage, compute_verdict

logger = logging.getLogger(__name__)
_CACHE_TTL_SECONDS = 60 * 10  # 10 minutes per Phase 8 spec
_ResultType = TypeVar("_ResultType")

_BRAND_CATALOG: BrandCatalog | None = None


def _brand_catalog() -> BrandCatalog:
    global _BRAND_CATALOG
    if _BRAND_CATALOG is None:
        try:
            _BRAND_CATALOG = load_brands()
        except Exception as error:  # noqa: BLE001 - brand file optional
            logger.warning("brand catalogue unavailable (%s)", type(error).__name__)
            _BRAND_CATALOG = BrandCatalog()
    return _BRAND_CATALOG


class InfrastructureBundle(BaseModel):
    """Combined registration and DNS results for one web destination."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["AVAILABLE", "UNAVAILABLE"]
    domain_age_days: int | None
    indicators: list[Indicator]
    features: dict[str, float | int | bool]


class FastPathResult(BaseModel):
    """Typed analysis result shared by API and downstream library callers."""

    model_config = ConfigDict(extra="forbid")

    classification: InputClassification
    analysis_payload: str
    domain: str | None
    is_punycode: bool
    shannon_entropy: float
    domain_age_days: int | None
    threat_feed_matches: int
    advisory_report: AdvisoryReport
    checks: list[CheckResult] = []
    verdict: Literal["DANGEROUS", "SUSPICIOUS", "LIKELY_SAFE", "UNKNOWN"] = "UNKNOWN"
    risk_score: int = 0
    risk_score_note: str = "Heuristic risk score, not a probability."
    coverage_level: Literal["low", "medium", "high"] = "low"


async def run_fast_path(
    raw_input: str,
    *,
    redis_client: redis.Redis | None = None,
    settings: Settings | None = None,
    domain_repository: Callable[..., Any] | None = None,
) -> FastPathResult:
    """Classify input, run bounded checks concurrently, and cache the result."""
    current_settings = settings or get_settings()
    routed = classify_and_route(raw_input)
    classification = InputClassification(
        payload_type=routed.payload_type,  # type: ignore[arg-type]
        normalized_payload=routed.normalized_payload,
        embedded_payload=routed.embedded_payload,
        recognized=routed.recognized,
    )
    analysis_payload = routed.embedded_payload or routed.normalized_payload
    cache_key = _cache_key(routed.normalized_payload)
    deadline = (
        asyncio.get_running_loop().time() + current_settings.fast_path_budget_seconds
    )

    owned_redis = redis_client is None
    cache = redis_client or redis.from_url(current_settings.redis_url)
    try:
        try:
            cached_result = await _wait_for_remaining(
                _read_cache(cache, cache_key), deadline
            )
        except TimeoutError:
            cached_result = None
            remaining_budget = 0.0
        else:
            remaining_budget = max(0.0, deadline - asyncio.get_running_loop().time())
        if cached_result is not None:
            return cached_result

        result = await _analyze(
            routed,
            classification,
            analysis_payload,
            cache,
            current_settings,
            domain_repository=domain_repository,
            budget_seconds=remaining_budget,
        )
        try:
            await _wait_for_remaining(_write_cache(cache, cache_key, result), deadline)
        except TimeoutError:
            logger.info("fast-path cache write exceeded the remaining time budget")
        except Exception:  # noqa: BLE001 - non-critical cache write
            logger.info("fast-path cache write failed")
        return result
    finally:
        if owned_redis:
            try:
                await cache.aclose()
            except (RedisError, OSError):
                logger.info("fast-path cache connection close failed")


async def _analyze(
    routed: RouteResult,
    classification: InputClassification,
    payload: str,
    cache: redis.Redis,
    settings: Settings,
    *,
    domain_repository: Callable[..., Any] | None,
    budget_seconds: float,
) -> FastPathResult:
    """Run bounded checks through the runner and compute verdict + coverage."""
    domain = routed.registrable_domain
    is_web_payload = classification.payload_type == "URL" or (
        classification.payload_type == "QR_TEXT"
        and payload.lower().startswith(("http://", "https://"))
    )
    needs_upi = (
        classification.payload_type == "UPI_DEEP_LINK"
        or (
            classification.payload_type == "QR_TEXT"
            and payload.lower().startswith("upi://")
        )
        or (is_web_payload and _has_upi_query(payload))
    )

    catalog = _brand_catalog()

    async def lexical_check(_ctx: Any) -> Any:
        return await _run_lexical(payload)

    async def infra_check(_ctx: Any) -> Any:
        return await _run_infrastructure(domain, cache, settings, domain_repository)

    async def feeds_check(_ctx: Any) -> Any:
        return await _run_feeds(payload, cache, settings)

    async def upi_check(_ctx: Any) -> Any:
        return await _run_upi(payload)

    named_checks: list[tuple[str, Callable[[Any], Any], CheckGroup]] = [
        ("lexical", lexical_check, "lexical"),
        ("infrastructure", infra_check, "infrastructure"),
        ("threat_feeds", feeds_check, "external_reputation"),
    ]
    if needs_upi:
        named_checks.append(("upi", upi_check, "transaction"))

    check_results = await run_checks(
        [
            CheckSpec(
                name=name,
                fn=fn,
                timeout_s=settings.fast_path_budget_seconds,
                group=group,
            )
            for name, fn, group in named_checks
        ],
        payload,
    )

    report = build_report(
        check_results["lexical"],
        check_results["infrastructure"],
        check_results["threat_feeds"],
        check_results.get("upi") if needs_upi else None,
        None,
        payload_type=classification.payload_type,
        web_payload=is_web_payload,
    )
    coverage = compute_coverage(check_results)
    verdict, score, _reason_ids = compute_verdict(check_results, coverage)
    features = _features(check_results["lexical"])
    entropy = _finite_number(
        features.get("shannon_entropy", features.get("entropy", 0.0))
    )
    is_punycode = bool(features.get("is_punycode", _host_has_punycode(payload)))
    feed_result = check_results["threat_feeds"]
    return FastPathResult(
        classification=classification,
        analysis_payload=payload,
        domain=routed.host.raw if routed.host else None,
        is_punycode=is_punycode,
        shannon_entropy=entropy,
        domain_age_days=_domain_age(check_results["infrastructure"]),
        threat_feed_matches=int(feed_result.detail.get("gsb_match_count", 0))
        + int(feed_result.detail.get("vt_malicious_count", 0)),
        advisory_report=report,
        checks=list(check_results.values()),
        verdict=verdict,
        risk_score=score,
        coverage_level=coverage.level,
    )


async def _run_lexical(payload: str) -> Any:
    """Kept for backward compatibility with existing tests that monkeypatch it."""
    try:
        module = importlib.import_module("app.core.lexical")
        checker = module.analyze_url
    except (ImportError, AttributeError):
        return _unavailable_check("Lexical URL analysis")
    try:
        if inspect.iscoroutinefunction(checker):
            return await checker(payload)
        return await asyncio.to_thread(checker, payload)
    except (TimeoutError, OSError, ValueError, TypeError) as error:
        logger.info("lexical check unavailable (%s)", type(error).__name__)
        return _unavailable_check("Lexical URL analysis")
    except Exception as error:  # noqa: BLE001 - isolate a failed optional check
        logger.warning("lexical check failed (%s)", type(error).__name__)
        return _unavailable_check("Lexical URL analysis")


async def _run_infrastructure(
    domain: str,
    cache: redis.Redis,
    settings: Settings,
    repository: Callable[..., Any] | None,
) -> InfrastructureBundle:
    try:
        domain_result, dns_result = await asyncio.gather(
            get_domain_info(
                domain,
                repository=repository,
                redis_client=cache,
                settings=settings,
            ),
            resolve_dns(domain, settings=settings),
            return_exceptions=True,
        )
    except (TimeoutError, OSError, ValueError) as error:
        logger.info("infrastructure checks unavailable (%s)", type(error).__name__)
        return _unavailable_infrastructure()
    indicators: list[Indicator] = []
    age_days = None
    status_unavailable = False
    if isinstance(domain_result, DomainInfo):
        indicators.extend(domain_result.indicators)
        age_days = domain_result.domain_age_days
        status_unavailable |= domain_result.status == "UNKNOWN"
    elif isinstance(domain_result, asyncio.CancelledError):
        raise domain_result
    else:
        status_unavailable = True
        indicators.extend(_indicators_from_error(domain_result, "Domain registration"))
    if isinstance(dns_result, DnsInfo):
        indicators.extend(dns_result.indicators)
        status_unavailable |= dns_result.status == "UNAVAILABLE"
    elif isinstance(dns_result, asyncio.CancelledError):
        raise dns_result
    else:
        status_unavailable = True
        indicators.extend(_indicators_from_error(dns_result, "DNS"))
    return InfrastructureBundle(
        status="UNAVAILABLE" if status_unavailable else "AVAILABLE",
        domain_age_days=age_days,
        indicators=indicators,
        features={"domain_age_days": age_days if age_days is not None else -1},
    )


async def _run_feeds(
    payload: str, cache: redis.Redis, settings: Settings
) -> ThreatFeedResult:
    try:
        return await check_threat_feeds(payload, redis_client=cache, settings=settings)
    except (TimeoutError, OSError, ValueError, TypeError) as error:
        logger.info("threat-feed check unavailable (%s)", type(error).__name__)
        return _unavailable_feed_result()
    except Exception as error:  # noqa: BLE001 - isolate a failed optional check
        logger.warning("threat-feed check failed (%s)", type(error).__name__)
        return _unavailable_feed_result()


async def _run_upi(payload: str) -> UpiResult:
    try:
        return analyze_upi(payload)
    except (ValueError, TypeError) as error:
        logger.info("UPI analysis unavailable (%s)", type(error).__name__)
        return _unavailable_check("UPI analysis")
    except Exception as error:  # noqa: BLE001 - isolate a failed optional check
        logger.warning("UPI analysis failed (%s)", type(error).__name__)
        return _unavailable_check("UPI analysis")


async def _immediate(value: Any) -> Any:
    return value


def _task_result(task: asyncio.Task[Any] | None, default: Any) -> Any:
    if task is None or not task.done() or task.cancelled():
        return default
    try:
        return task.result()
    except (TimeoutError, OSError, ValueError, TypeError, RedisError) as error:
        logger.info("fast-path check unavailable (%s)", type(error).__name__)
        return default
    except Exception as error:  # noqa: BLE001 - isolate a failed optional check
        logger.warning("fast-path check failed (%s)", type(error).__name__)
        return default


def _unavailable_check(name: str) -> dict[str, Any]:
    return {
        "status": "UNAVAILABLE",
        "indicators": [
            Indicator(
                code="CHECK_UNAVAILABLE",
                severity="info",
                message=f"{name} could not be checked during this scan.",
                evidence={"check": name, "status": "UNAVAILABLE"},
            )
        ],
        "features": {},
    }


def _unavailable_infrastructure() -> InfrastructureBundle:
    return InfrastructureBundle(
        status="UNAVAILABLE",
        domain_age_days=None,
        indicators=[
            Indicator(
                code="INFRASTRUCTURE_UNAVAILABLE",
                severity="info",
                message="Domain and DNS checks could not be completed.",
                evidence={"status": "UNAVAILABLE"},
            )
        ],
        features={"domain_age_days": -1},
    )


def _unavailable_feed_result() -> ThreatFeedResult:
    indicator = Indicator(
        code="THREAT_FEED_UNAVAILABLE",
        severity="info",
        message="Threat-list checks could not be completed.",
        evidence={"status": "UNAVAILABLE"},
    )
    unavailable = FeedLookup(status="UNAVAILABLE", indicators=[indicator])
    return ThreatFeedResult(
        google_safe_browsing=unavailable,
        virustotal=unavailable,
        indicators=[indicator],
        features={
            "gsb_match_count": 0,
            "vt_malicious_count": 0,
            "vt_total_count": 0,
            "gsb_available": False,
            "vt_available": False,
        },
    )


def _indicators_from_error(error: Any, label: str) -> list[Indicator]:
    return [
        Indicator(
            code="CHECK_UNAVAILABLE",
            severity="info",
            message=f"{label} could not be completed ({type(error).__name__}).",
            evidence={"check": label, "status": "UNAVAILABLE"},
        )
    ]


def _domain_from_web_url(payload: str) -> str | None:
    try:
        parsed = urlsplit(payload if "://" in payload else f"https://{payload}")
        host = parsed.hostname
    except ValueError:
        return None
    if not host:
        return None
    return host.lower()


def _analysis_payload(classification: InputClassification) -> str:
    payload = classification.embedded_payload or classification.normalized_payload
    if classification.payload_type == "URL" and "://" not in payload:
        return f"https://{payload}"
    return payload


def _host_has_punycode(payload: str) -> bool:
    try:
        host = urlsplit(payload if "://" in payload else f"https://{payload}").hostname
    except ValueError:
        return False
    return bool(
        host and any(label.startswith("xn--") for label in host.lower().split("."))
    )


def _has_upi_query(payload: str) -> bool:
    query = urlsplit(
        payload if "://" in payload else f"https://{payload}"
    ).query.lower()
    return bool(re.search(r"(?:^|&)(?:pa|pn)=", query))


def _domain_age(infra: Any) -> int | None:
    value = getattr(infra, "domain_age_days", None)
    return value if isinstance(value, int) else None


def _features(result: Any) -> Mapping[str, Any]:
    features = getattr(result, "features", {})
    return features if isinstance(features, Mapping) else {}


def _finite_number(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) else 0.0


def _indicators_from_value(value: Any) -> list[Indicator]:
    raw = getattr(value, "indicators", [])
    return [item for item in raw if isinstance(item, Indicator)]


def _cache_key(normalized_input: str) -> str:
    digest = hashlib.sha256(normalized_input.encode("utf-8")).hexdigest()
    return f"fast-path:{digest}"


async def _read_cache(cache: redis.Redis, key: str) -> FastPathResult | None:
    try:
        raw = await cache.get(key)
    except (RedisError, OSError):
        return None
    if raw is None:
        return None
    try:
        return FastPathResult.model_validate_json(raw)
    except Exception:  # noqa: BLE001 - corrupt cache is treated as a miss
        return None


async def _write_cache(cache: redis.Redis, key: str, result: FastPathResult) -> None:
    try:
        await cache.setex(key, _CACHE_TTL_SECONDS, result.model_dump_json())
    except (RedisError, OSError) as error:
        logger.info("fast-path cache write unavailable (%s)", type(error).__name__)


async def _wait_for_remaining(
    awaitable: Awaitable[_ResultType], deadline: float
) -> _ResultType:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise TimeoutError("no budget remaining")
    return await asyncio.wait_for(awaitable, timeout=remaining)
