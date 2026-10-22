"""Domain age and DNS checks with bounded time and explainable results."""

import asyncio
import hashlib
import inspect
import ipaddress
import json
import logging
import re
from collections.abc import Awaitable, Callable
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

import asyncwhois
import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
import idna
import redis.asyncio as redis
from pydantic import BaseModel, ConfigDict, ValidationError
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings, get_settings
from app.core.models import Indicator
from app.core.netguard import BlockedTargetError, assert_public_target
from app.db.models import DomainRecord
from app.db.session import get_async_engine

logger = logging.getLogger(__name__)
_UTC = timezone.utc  # noqa: UP017 - local validation runtime is Python 3.10
_ASYNC_TIMEOUT_ERROR = asyncio.TimeoutError
_DOMAIN_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

_WHOIS_CACHE_TTL_SECONDS = 24 * 60 * 60
_DOMAIN_RECORD_TTL = timedelta(days=7)
_DNS_BOOTSTRAP_PATH = Path(__file__).resolve().parents[2] / "data" / "dns.json"
_DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS")


class DomainInfo(BaseModel):
    """Domain registration age with UNKNOWN represented explicitly."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["KNOWN", "UNKNOWN"]
    domain_age_days: int | None
    registered_at: datetime | None
    registrar: str | None
    indicators: list[Indicator]


class DnsInfo(BaseModel):
    """DNS record counts and associated explainable indicators."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["AVAILABLE", "UNAVAILABLE"]
    record_counts: dict[str, int]
    minimum_a_ttl: int | None
    indicators: list[Indicator]


class _RdapRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    registered_at: datetime | None
    registrar: str | None


DomainRepository = Callable[[str], Awaitable[object | None] | object | None]


async def get_domain_info(
    domain: str,
    *,
    repository: DomainRepository | None = None,
    redis_client: redis.Redis | None = None,
    http_client: httpx.AsyncClient | None = None,
    settings: Settings | None = None,
) -> DomainInfo:
    """Use a fresh database record, then RDAP, then WHOIS under one timeout."""
    current_settings = settings or get_settings()
    normalized_domain = _normalize_domain(domain)
    if normalized_domain is None:
        return _unknown_domain_info()

    owned_redis = redis_client is None
    cache = redis_client or redis.from_url(current_settings.redis_url)
    try:
        try:
            record = await _read_repository(repository, normalized_domain)
            cached = _domain_record_to_info(record)
            if cached is not None:
                return cached
        except (SQLAlchemyError, OSError, RuntimeError, ValueError):
            logger.info(
                "domain record cache unavailable; continuing with registry lookup"
            )

        owned_http = http_client is None
        client = http_client or httpx.AsyncClient(
            timeout=current_settings.whois_timeout_seconds
        )
        try:
            record = await asyncio.wait_for(
                _rdap_then_whois(normalized_domain, cache, client, current_settings),
                timeout=current_settings.whois_timeout_seconds,
            )
        except (
            _ASYNC_TIMEOUT_ERROR,
            asyncwhois.WhoIsError,
            httpx.HTTPError,
            OSError,
            ValueError,
            TypeError,
            KeyError,
            ValidationError,
            RedisError,
            SQLAlchemyError,
            RuntimeError,
        ) as error:
            logger.info(
                "domain registration lookup unavailable (%s)", type(error).__name__
            )
            return _unknown_domain_info()
        finally:
            if owned_http:
                await client.aclose()
        return _domain_info_from_registration(record.registered_at, record.registrar)
    finally:
        if owned_redis:
            try:
                await cache.aclose()
            except (RedisError, OSError):
                logger.info("domain registration cache connection close failed")


async def resolve_dns(
    domain: str,
    *,
    resolver: dns.asyncresolver.Resolver | None = None,
    settings: Settings | None = None,
) -> DnsInfo:
    """Resolve public-domain DNS records and report basic availability clues."""
    current_settings = settings or get_settings()
    normalized_domain = _normalize_domain(domain)
    if normalized_domain is None:
        return _dns_unavailable("The domain name is invalid.")
    try:
        await assert_public_target(
            normalized_domain,
            settings=current_settings,
        )
    except BlockedTargetError:
        return _dns_unavailable("The domain did not pass the public-target check.")
    except (TimeoutError, OSError, dns.exception.DNSException, ValueError):
        logger.info("domain public-target check unavailable")
        return _dns_unavailable("The domain public-target check could not complete.")

    dns_resolver = resolver or dns.asyncresolver.Resolver()
    results = await asyncio.gather(
        *(
            _resolve_dns_records(
                dns_resolver,
                normalized_domain,
                record_type,
                current_settings.dns_timeout_seconds,
            )
            for record_type in _DNS_RECORD_TYPES
        ),
        return_exceptions=True,
    )
    records: dict[str, list[str]] = {}
    failed_record_types: set[str] = set()
    query_failures: list[str] = []
    for record_type, result in zip(_DNS_RECORD_TYPES, results, strict=True):
        if isinstance(result, asyncio.CancelledError):
            raise result
        if isinstance(result, Exception):
            query_failures.append(record_type)
            failed_record_types.add(record_type)
            records[record_type] = []
        else:
            records[record_type], _ = result

    counts = {
        record_type: len(records[record_type]) for record_type in _DNS_RECORD_TYPES
    }
    indicators: list[Indicator] = []
    if counts["A"] == 0 and "A" not in failed_record_types:
        indicators.append(
            Indicator(
                code="NO_A_RECORD",
                severity="info",
                message="No IPv4 A record was returned for this domain.",
                evidence={"a_record_count": 0},
            )
        )
    if counts["MX"] == 0 and "MX" not in failed_record_types:
        indicators.append(
            Indicator(
                code="NO_MX_RECORD",
                severity="info",
                message="No mail-server MX record was returned; many legitimate sites have none.",
                evidence={"mx_record_count": 0},
            )
        )
    min_a_ttl = min(ttils) if (ttils := _answer_ttls(results, "A")) else None
    if counts["A"] >= 5 and min_a_ttl is not None and min_a_ttl <= 60:
        indicators.append(
            Indicator(
                code="FAST_FLUX_LIKE",
                severity="low",
                message="Many IPv4 addresses have a very short DNS lifetime; this can be a fast-flux-like pattern.",
                evidence={
                    "a_record_count": counts["A"],
                    "minimum_ttl_seconds": min_a_ttl,
                },
            )
        )
    if query_failures:
        indicators.append(
            Indicator(
                code="DNS_LOOKUP_UNAVAILABLE",
                severity="info",
                message="Some DNS records could not be checked at this time.",
                evidence={
                    "record_queries_failed": len(query_failures),
                    "failed_record_types": ",".join(query_failures),
                },
            )
        )
    return DnsInfo(
        status="UNAVAILABLE" if query_failures else "AVAILABLE",
        record_counts=counts,
        minimum_a_ttl=min_a_ttl,
        indicators=indicators,
    )


async def _rdap_then_whois(
    domain: str,
    cache: redis.Redis,
    client: httpx.AsyncClient,
    settings: Settings,
) -> _RdapRecord:
    redis_key = f"domain-rdap:{hashlib.sha256(domain.encode()).hexdigest()}"
    try:
        cached_value = await cache.get(redis_key)
    except (RedisError, OSError):
        cached_value = None
    if cached_value:
        try:
            return _RdapRecord.model_validate_json(cached_value)
        except (ValueError, TypeError):
            logger.info("cached domain registration record was invalid")

    rdap_record = await _lookup_rdap(domain, client)
    if rdap_record is not None and rdap_record.registered_at is not None:
        try:
            await cache.setex(
                redis_key,
                _WHOIS_CACHE_TTL_SECONDS,
                rdap_record.model_dump_json(),
            )
        except (RedisError, OSError):
            logger.info("domain registration cache unavailable")
        return rdap_record

    try:
        whois_result = await asyncwhois.aio_whois_domain(
            domain,
            timeout=max(1, int(settings.whois_timeout_seconds)),
        )
        parser_output = whois_result.parser_output
        registered_at = _parse_datetime(parser_output.get("creation_date"))
        registrar = _string_value(parser_output.get("registrar"))
        record = _RdapRecord(registered_at=registered_at, registrar=registrar)
        if registered_at is not None:
            try:
                await cache.setex(
                    redis_key,
                    _WHOIS_CACHE_TTL_SECONDS,
                    record.model_dump_json(),
                )
            except (RedisError, OSError):
                logger.info("domain registration cache unavailable")
        return record
    except (
        asyncwhois.WhoIsError,
        TimeoutError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ) as error:
        logger.info("WHOIS fallback unavailable (%s)", type(error).__name__)
        if rdap_record is not None:
            return rdap_record
        raise


async def _lookup_rdap(domain: str, client: httpx.AsyncClient) -> _RdapRecord | None:
    try:
        endpoint = _rdap_endpoint(domain)
        if endpoint is None:
            return None
        response = await client.get(f"{endpoint.rstrip('/')}/domain/{domain}")
        response.raise_for_status()
        return _rdap_record(response.json())
    except (
        httpx.HTTPError,
        OSError,
        TimeoutError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        json.JSONDecodeError,
    ):
        logger.info("RDAP lookup unavailable")
        return None


def _rdap_endpoint(domain: str) -> str | None:
    with _DNS_BOOTSTRAP_PATH.open(encoding="utf-8") as bootstrap_file:
        bootstrap = json.load(bootstrap_file)
    tld = domain.rsplit(".", maxsplit=1)[-1].lower()
    for suffixes, urls in bootstrap["services"]:
        if tld in {str(suffix).lower() for suffix in suffixes}:
            for url in urls:
                if str(url).lower().startswith("https://"):
                    return str(url)
            return None
    return None


def _rdap_record(payload: Any) -> _RdapRecord:
    registered_at = None
    registrar = None
    if isinstance(payload, dict):
        for event in payload.get("events", []):
            if event.get("eventAction", "").lower() in {"registration", "registered"}:
                registered_at = _parse_datetime(event.get("eventDate"))
                if registered_at is not None:
                    break
        for entity in payload.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray")
                registrar = _registrar_from_vcard(vcard)
                if registrar:
                    break
    return _RdapRecord(registered_at=registered_at, registrar=registrar)


def _registrar_from_vcard(vcard: Any) -> str | None:
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            return _string_value(item[3])
    return None


async def _read_repository(
    repository: DomainRepository | None, domain: str
) -> object | None:
    if repository is not None:
        result = repository(domain)
        return await result if inspect.isawaitable(result) else result
    session_factory = async_sessionmaker(get_async_engine(), class_=AsyncSession)
    async with session_factory() as session:
        return await session.scalar(
            select(DomainRecord).where(DomainRecord.domain_name == domain)
        )


def _domain_record_to_info(record: object | None) -> DomainInfo | None:
    if record is None:
        return None
    updated_at = getattr(record, "updated_at", None)
    if not isinstance(updated_at, datetime):
        return None
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=_UTC)
    if datetime.now(_UTC) - updated_at > _DOMAIN_RECORD_TTL:
        return None
    registered_at = _parse_datetime(getattr(record, "registered_at", None))
    registrar = _string_value(getattr(record, "registrar", None))
    return _domain_info_from_registration(registered_at, registrar)


def _domain_info_from_registration(
    registered_at: datetime | None, registrar: str | None
) -> DomainInfo:
    if registered_at is None:
        return _unknown_domain_info(registrar=registrar)
    age_days = (datetime.now(_UTC).date() - registered_at.date()).days
    if age_days < 0:
        return _unknown_domain_info(registrar=registrar)

    indicators: list[Indicator] = []
    if age_days < 7:
        severity = "high"
    elif age_days < 30:
        severity = "medium"
    elif age_days < 90:
        severity = "low"
    else:
        severity = None
    if severity is not None:
        indicators.append(
            Indicator(
                code="DOMAIN_VERY_NEW",
                severity=severity,
                message=f"This domain was registered {age_days} days ago; new domains deserve extra scrutiny.",
                evidence={"domain_age_days": age_days},
            )
        )
    if registrar and any(
        word in registrar.casefold() for word in ("privacy", "proxy", "protection")
    ):
        indicators.append(
            Indicator(
                code="REGISTRAR_PRIVACY_PROXY",
                severity="info",
                message="The registration lists a privacy or proxy service; this alone does not indicate abuse.",
                evidence={"registrar": registrar},
            )
        )
    return DomainInfo(
        status="KNOWN",
        domain_age_days=age_days,
        registered_at=registered_at,
        registrar=registrar,
        indicators=indicators,
    )


def _unknown_domain_info(*, registrar: str | None = None) -> DomainInfo:
    return DomainInfo(
        status="UNKNOWN",
        domain_age_days=None,
        registered_at=None,
        registrar=registrar,
        indicators=[
            Indicator(
                code="WHOIS_TIMEOUT_OR_UNAVAILABLE",
                severity="info",
                message="The domain registration age is unknown because the registry lookup did not provide a usable date.",
                evidence={"domain_age_days": None},
            )
        ],
    )


async def _resolve_dns_records(
    resolver: dns.asyncresolver.Resolver, domain: str, record_type: str, timeout: float
) -> tuple[list[str], list[int]]:
    try:
        answer = await asyncio.wait_for(
            resolver.resolve(domain, record_type, lifetime=timeout),
            timeout=timeout,
        )
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [], []
    record_values = [str(getattr(record, "address", record)) for record in answer]
    rrset = getattr(answer, "rrset", None)
    ttl = int(rrset.ttl) if rrset is not None else None
    ttls = [ttl] * len(record_values) if ttl is not None else []
    return record_values, ttls


def _dns_unavailable(message: str) -> DnsInfo:
    return DnsInfo(
        status="UNAVAILABLE",
        record_counts={record_type: 0 for record_type in _DNS_RECORD_TYPES},
        minimum_a_ttl=None,
        indicators=[
            Indicator(
                code="DNS_LOOKUP_UNAVAILABLE",
                severity="info",
                message=message,
                evidence={"record_queries_failed": len(_DNS_RECORD_TYPES)},
            )
        ],
    )


def _answer_ttls(results: list[Any], record_type: str) -> list[int]:
    index = _DNS_RECORD_TYPES.index(record_type)
    result = results[index]
    if isinstance(result, BaseException):
        return []
    return result[1]


def _normalize_domain(domain: str) -> str | None:
    if not isinstance(domain, str):
        return None
    normalized = domain.strip().rstrip(".").lower()
    if not normalized or "/" in normalized or "@" in normalized or "://" in normalized:
        return None
    try:
        ipaddress.ip_address(normalized)
        return None
    except ValueError:
        pass
    try:
        normalized = idna.encode(normalized, uts46=True, std3_rules=True).decode(
            "ascii"
        )
    except idna.IDNAError:
        return None
    labels = normalized.split(".")
    if (
        len(normalized) > 253
        or len(labels) < 2
        or any(not _DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels)
    ):
        return None
    return normalized


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, datetime.min.time(), _UTC)
    elif isinstance(value, list):
        for item in value:
            parsed = _parse_datetime(item)
            if parsed is not None:
                return parsed
        return None
    elif isinstance(value, str):
        try:
            normalized_value = f"{value[:-1]}+00:00" if value.endswith("Z") else value
            parsed = datetime.fromisoformat(normalized_value)
        except ValueError:
            try:
                parsed = datetime.combine(
                    date.fromisoformat(value[:10]), datetime.min.time()
                )
            except ValueError:
                return None
    else:
        return None
    return parsed.replace(tzinfo=_UTC) if parsed.tzinfo is None else parsed


def _string_value(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, list):
        return next(
            (item.strip() for item in value if isinstance(item, str) and item.strip()),
            None,
        )
    return None
