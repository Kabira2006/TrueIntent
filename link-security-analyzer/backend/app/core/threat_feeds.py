"""Privacy-conscious lookups against existing threat-feed reports."""

import asyncio
import base64
import hashlib
import logging
import time
from typing import Literal
from urllib.parse import quote

import httpx
import redis.asyncio as redis
from pydantic import BaseModel, ConfigDict, ValidationError
from redis.exceptions import RedisError

from app.config import Settings, get_settings
from app.core.models import Indicator

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 24 * 60 * 60
_VT_LIMIT_SCRIPT = """
local minute_count = redis.call('INCR', KEYS[1])
if minute_count == 1 then redis.call('EXPIRE', KEYS[1], 60) end
if minute_count > 4 then return 0 end
local day_count = redis.call('INCR', KEYS[2])
if day_count == 1 then redis.call('EXPIRE', KEYS[2], 86400) end
if day_count > 500 then return 0 end
return 1
"""
FeedStatus = Literal["MATCH", "NO_MATCH", "NO_REPORT", "UNAVAILABLE"]


class FeedLookup(BaseModel):
    """One feed's status and any findings."""

    model_config = ConfigDict(extra="forbid")

    status: FeedStatus
    indicators: list[Indicator]
    malicious_count: int = 0
    total_count: int = 0


class ThreatFeedResult(BaseModel):
    """Combined result from Google Safe Browsing and VirusTotal."""

    model_config = ConfigDict(extra="forbid")

    google_safe_browsing: FeedLookup
    virustotal: FeedLookup
    indicators: list[Indicator]
    features: dict[str, int | bool]


async def check_threat_feeds(
    url: str,
    *,
    redis_client: redis.Redis | None = None,
    http_client: httpx.AsyncClient | None = None,
    settings: Settings | None = None,
) -> ThreatFeedResult:
    """Look up prior reports only; never upload the URL to VirusTotal."""
    current_settings = settings or get_settings()
    owned_redis = redis_client is None
    cache = redis_client or redis.from_url(current_settings.redis_url)
    owned_http = http_client is None
    client = http_client or httpx.AsyncClient(
        timeout=current_settings.threat_feed_timeout_seconds
    )
    try:
        gsb, vt = await asyncio.gather(
            lookup_google_safe_browsing(
                url,
                redis_client=cache,
                http_client=client,
                settings=current_settings,
            ),
            lookup_virustotal(
                url,
                redis_client=cache,
                http_client=client,
                settings=current_settings,
            ),
        )
        indicators = [*gsb.indicators, *vt.indicators]
        return ThreatFeedResult(
            google_safe_browsing=gsb,
            virustotal=vt,
            indicators=indicators,
            features={
                "gsb_match_count": (
                    int(gsb.indicators[0].evidence.get("match_count", 0))
                    if gsb.indicators
                    else 0
                ),
                "vt_malicious_count": vt.malicious_count,
                "vt_total_count": vt.total_count,
                "gsb_available": gsb.status != "UNAVAILABLE",
                "vt_available": vt.status != "UNAVAILABLE",
            },
        )
    finally:
        if owned_http:
            await client.aclose()
        if owned_redis:
            try:
                await cache.aclose()
            except (RedisError, OSError):
                logger.info("threat-feed cache connection close failed")


async def lookup_google_safe_browsing(
    url: str,
    *,
    redis_client: redis.Redis,
    http_client: httpx.AsyncClient,
    settings: Settings | None = None,
) -> FeedLookup:
    """Check Google Safe Browsing for an existing match."""
    current_settings = settings or get_settings()
    if not current_settings.gsb_api_key:
        return _unavailable("Google Safe Browsing")

    key = _cache_key("gsb", url)
    cached = await _read_cache(redis_client, key)
    if cached is not None:
        return cached

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    request_body = {
        "client": {"clientId": "trueintent", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = await http_client.post(
            endpoint,
            params={"key": current_settings.gsb_api_key},
            json=request_body,
        )
        response.raise_for_status()
        payload = response.json()
        matches = payload.get("matches", []) if isinstance(payload, dict) else []
        if matches:
            result = FeedLookup(
                status="MATCH",
                indicators=[
                    Indicator(
                        code="GSB_MATCH",
                        severity="high",
                        message="Google's browsing threat list has a prior match for this URL.",
                        evidence={
                            "match_count": len(matches),
                            "threat_types": ",".join(
                                sorted(
                                    {
                                        str(match.get("threatType", "unknown"))
                                        for match in matches
                                    }
                                )
                            ),
                        },
                    )
                ],
            )
        else:
            result = FeedLookup(status="NO_MATCH", indicators=[])
    except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError) as error:
        logger.info(
            "Google Safe Browsing lookup unavailable (%s)", type(error).__name__
        )
        return _unavailable("Google Safe Browsing")
    await _write_cache(redis_client, key, result)
    return result


async def lookup_virustotal(
    url: str,
    *,
    redis_client: redis.Redis,
    http_client: httpx.AsyncClient,
    settings: Settings | None = None,
    now: float | None = None,
) -> FeedLookup:
    """Look up a URL's existing VirusTotal report without submitting it."""
    current_settings = settings or get_settings()
    if not current_settings.vt_api_key:
        return _unavailable("VirusTotal")

    key = _cache_key("vt", url)
    cached = await _read_cache(redis_client, key)
    if cached is not None:
        return cached
    try:
        allowed = await _within_virustotal_limits(redis_client, now=now)
    except (RedisError, OSError) as error:
        logger.info("VirusTotal rate limiter unavailable (%s)", type(error).__name__)
        return _unavailable("VirusTotal")
    if not allowed:
        return _unavailable("VirusTotal rate limit reached")

    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{quote(url_id, safe='')}"
    try:
        response = await http_client.get(
            endpoint,
            headers={"x-apikey": current_settings.vt_api_key},
        )
        if response.status_code == 404:
            result = FeedLookup(status="NO_REPORT", indicators=[])
        else:
            response.raise_for_status()
            payload = response.json()
            stats = payload["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            total = sum(int(count) for count in stats.values())
            result = _virustotal_result(malicious, total)
    except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError) as error:
        logger.info("VirusTotal lookup unavailable (%s)", type(error).__name__)
        return _unavailable("VirusTotal")
    await _write_cache(redis_client, key, result)
    return result


async def _within_virustotal_limits(
    cache: redis.Redis, *, now: float | None = None
) -> bool:
    current_time = time.time() if now is None else now
    minute_bucket = int(current_time // 60)
    day_bucket = int(current_time // 86400)
    result = await cache.eval(
        _VT_LIMIT_SCRIPT,
        2,
        f"threat-feed:vt:minute:{minute_bucket}",
        f"threat-feed:vt:day:{day_bucket}",
    )
    return bool(result)


def _virustotal_result(malicious: int, total: int) -> FeedLookup:
    indicators: list[Indicator] = []
    status: FeedStatus = "NO_MATCH"
    if malicious > 0:
        status = "MATCH"
        if malicious >= 6:
            severity = "high"
        elif malicious >= 3:
            severity = "medium"
        else:
            severity = "low"
        indicators.append(
            Indicator(
                code="VT_MALICIOUS_VENDORS",
                severity=severity,
                message=f"{malicious} of {total} VirusTotal vendors flagged this URL.",
                evidence={"malicious_vendors": malicious, "total_vendors": total},
            )
        )
    return FeedLookup(
        status=status,
        indicators=indicators,
        malicious_count=malicious,
        total_count=total,
    )


async def _read_cache(cache: redis.Redis, key: str) -> FeedLookup | None:
    try:
        cached = await cache.get(key)
        if cached is None:
            return None
        return FeedLookup.model_validate_json(cached)
    except (RedisError, OSError, ValidationError, ValueError, TypeError) as error:
        logger.info("threat-feed cache read unavailable (%s)", type(error).__name__)
        return None


async def _write_cache(cache: redis.Redis, key: str, result: FeedLookup) -> None:
    try:
        await cache.setex(key, _CACHE_TTL_SECONDS, result.model_dump_json())
    except (RedisError, OSError) as error:
        logger.info("threat-feed cache write unavailable (%s)", type(error).__name__)


def _cache_key(feed: str, url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return f"threat-feed:{feed}:{digest}"


def _unavailable(feed: str) -> FeedLookup:
    display_name = (
        "Google threat list" if feed == "Google Safe Browsing" else feed
    )
    return FeedLookup(
        status="UNAVAILABLE",
        indicators=[
            Indicator(
                code="THREAT_FEED_UNAVAILABLE",
                severity="info",
                message=f"{display_name} could not be checked; this does not mean the URL is clear or harmful.",
                evidence={"feed": display_name, "status": "UNAVAILABLE"},
            )
        ],
    )
