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
import tldextract
from pydantic import BaseModel, ConfigDict
from redis.exceptions import RedisError

from app.config import Settings, get_settings
from app.core.aggregator import AdvisoryReport, build_report
from app.core.infrastructure import DnsInfo, DomainInfo, get_domain_info, resolve_dns
from app.core.input_router import classify_input
from app.core.models import Indicator, InputClassification
from app.core.threat_feeds import FeedLookup, ThreatFeedResult, check_threat_feeds
from app.core.upi import UpiResult, analyze_upi

logger = logging.getLogger(__name__)
_CACHE_TTL_SECONDS = 60 * 60
_SUFFIX_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
_ResultType = TypeVar("_ResultType")


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


async def run_fast_path(
    raw_input: str,
    *,
    redis_client: redis.Redis | None = None,
    settings: Settings | None = None,
    domain_repository: Callable[..., Any] | None = None,
) -> FastPathResult:
    """Classify input, run bounded checks concurrently, and cache the result."""
    current_settings = settings or get_settings()
    classification = classify_input(raw_input)
    analysis_payload = _analysis_payload(classification)
    cache_key = _cache_key(classification.normalized_payload)
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
        return result
    finally:
        if owned_redis:
            try:
                await cache.aclose()
            except (RedisError, OSError):
                logger.info("fast-path cache connection close failed")


async def _analyze(
    classification: InputClassification,
    payload: str,
    cache: redis.Redis,
    settings: Settings,
    *,
    domain_repository: Callable[..., Any] | None,
    budget_seconds: float,
) -> FastPathResult:
    domain = _domain_from_web_url(payload)
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
    lexical_task = asyncio.create_task(_run_lexical(payload))
    if is_web_payload and domain is not None:
        infra_task = asyncio.create_task(
            _run_infrastructure(domain, cache, settings, domain_repository)
        )
        feed_task = asyncio.create_task(_run_feeds(payload, cache, settings))
    else:
        infra_task = asyncio.create_task(_immediate(_unavailable_infrastructure()))
        feed_task = asyncio.create_task(_immediate(_unavailable_feed_result()))
    upi_task = asyncio.create_task(_run_upi(payload)) if needs_upi else None
    tasks = [lexical_task, infra_task, feed_task]
    if upi_task is not None:
        tasks.append(upi_task)

    _, pending = await asyncio.wait(
        tasks,
        timeout=budget_seconds,
        return_when=asyncio.ALL_COMPLETED,
    )
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)

    lexical = _task_result(lexical_task, _unavailable_check("Lexical URL analysis"))
    infra = _task_result(infra_task, _unavailable_infrastructure())
    feeds = _task_result(feed_task, _unavailable_feed_result())
    upi = (
        _task_result(upi_task, _unavailable_check("UPI analysis"))
        if upi_task is not None
        else None
    )
    if pending:
        for task in pending:
            if task is lexical_task:
                lexical = _unavailable_check("Lexical URL analysis")
            elif task is infra_task:
                infra = _unavailable_infrastructure()
            elif task is feed_task:
                feeds = _unavailable_feed_result()
            elif task is upi_task:
                upi = _unavailable_check("UPI analysis")

    upi_for_report = upi if needs_upi else None
    report = build_report(
        lexical,
        infra,
        feeds,
        upi_for_report,
        None,
        payload_type=classification.payload_type,
        web_payload=is_web_payload,
    )
    features = _features(lexical)
    entropy = _finite_number(
        features.get("shannon_entropy", features.get("entropy", 0.0))
    )
    is_punycode = bool(features.get("is_punycode", _host_has_punycode(payload)))
    return FastPathResult(
        classification=classification,
        analysis_payload=payload,
        domain=domain,
        is_punycode=is_punycode,
        shannon_entropy=entropy,
        domain_age_days=_domain_age(infra),
        threat_feed_matches=int(feeds.features.get("gsb_match_count", 0))
        + int(feeds.features.get("vt_malicious_count", 0)),
        advisory_report=report,
    )


async def _run_lexical(payload: str) -> Any:
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
            message=f"{label} checks could not be completed.",
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
    extracted = _SUFFIX_EXTRACTOR(host)
    registered_domain = extracted.top_domain_under_public_suffix
    return registered_domain or host


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
    query = urlsplit(payload).query.lower()
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
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, Indicator)]


def _cache_key(normalized_input: str) -> str:
    digest = hashlib.sha256(normalized_input.encode("utf-8")).hexdigest()
    return f"fast-path:{digest}"


async def _read_cache(cache: redis.Redis, key: str) -> FastPathResult | None:
    try:
        cached = await cache.get(key)
        return FastPathResult.model_validate_json(cached) if cached else None
    except (RedisError, OSError, ValueError, TypeError) as error:
        logger.info("fast-path cache read unavailable (%s)", type(error).__name__)
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
        raise TimeoutError
    return await asyncio.wait_for(awaitable, timeout=remaining)
