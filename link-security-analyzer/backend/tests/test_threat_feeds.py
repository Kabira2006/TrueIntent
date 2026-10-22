"""Threat-feed checks use mocked HTTP and Redis clients only."""

import base64

import httpx
import pytest

from app.config import Settings
from app.core import threat_feeds


class _Redis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.eval_calls: list[tuple] = []
        self.allow_vt = True

    async def get(self, key: str):
        return self.values.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self.values[key] = value

    async def eval(self, script: str, numkeys: int, *keys: str) -> int:
        self.eval_calls.append((script, numkeys, *keys))
        return int(self.allow_vt)

    async def aclose(self) -> None:
        return None


class _Response:
    def __init__(self, payload: dict, *, status_code: int = 200) -> None:
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://feed.example")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError(
                "feed error", request=request, response=response
            )

    def json(self) -> dict:
        return self.payload


class _HttpClient:
    def __init__(self, *, post_response=None, get_response=None) -> None:
        self.post_response = post_response or _Response({})
        self.get_response = get_response or _Response(
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "harmless": 3}
                    }
                }
            }
        )
        self.post_calls: list[tuple] = []
        self.get_calls: list[tuple] = []

    async def post(self, url: str, *, params: dict, json: dict):
        self.post_calls.append((url, params, json))
        return self.post_response

    async def get(self, url: str, *, headers: dict):
        self.get_calls.append((url, headers))
        return self.get_response

    async def aclose(self) -> None:
        return None


def _settings(**kwargs) -> Settings:
    return Settings(_env_file=None, **kwargs)


async def test_missing_keys_return_unavailable_without_http_calls() -> None:
    redis_client = _Redis()
    client = _HttpClient()
    result = await threat_feeds.check_threat_feeds(
        "https://example.com",
        redis_client=redis_client,  # type: ignore[arg-type]
        http_client=client,  # type: ignore[arg-type]
        settings=_settings(gsb_api_key="", vt_api_key=""),
    )
    assert result.google_safe_browsing.status == "UNAVAILABLE"
    assert result.virustotal.status == "UNAVAILABLE"
    assert not client.post_calls
    assert not client.get_calls


async def test_google_safe_browsing_match_has_high_severity() -> None:
    redis_client = _Redis()
    client = _HttpClient(
        post_response=_Response({"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})
    )
    result = await threat_feeds.lookup_google_safe_browsing(
        "https://example.com",
        redis_client=redis_client,  # type: ignore[arg-type]
        http_client=client,  # type: ignore[arg-type]
        settings=_settings(gsb_api_key="test-key"),
    )
    assert result.status == "MATCH"
    assert result.indicators[0].code == "GSB_MATCH"
    assert result.indicators[0].severity == "high"
    assert "https://example.com" in str(client.post_calls[0][2])
    assert client.post_calls[0][1] == {"key": "test-key"}


async def test_google_safe_browsing_no_match_is_cached() -> None:
    cache = _Redis()
    client = _HttpClient()
    settings = _settings(gsb_api_key="test-key")
    first = await threat_feeds.lookup_google_safe_browsing(
        "https://example.com",
        redis_client=cache,  # type: ignore[arg-type]
        http_client=client,  # type: ignore[arg-type]
        settings=settings,
    )
    second = await threat_feeds.lookup_google_safe_browsing(
        "https://example.com",
        redis_client=cache,  # type: ignore[arg-type]
        http_client=client,  # type: ignore[arg-type]
        settings=settings,
    )
    assert first.status == second.status == "NO_MATCH"
    assert len(client.post_calls) == 1
    assert next(iter(cache.values)).startswith("threat-feed:gsb:")


async def test_google_timeout_is_unavailable() -> None:
    class _TimeoutClient(_HttpClient):
        async def post(self, *args, **kwargs):
            raise httpx.TimeoutException("timeout")

    result = await threat_feeds.lookup_google_safe_browsing(
        "https://example.com",
        redis_client=_Redis(),  # type: ignore[arg-type]
        http_client=_TimeoutClient(),  # type: ignore[arg-type]
        settings=_settings(gsb_api_key="test-key"),
    )
    assert result.status == "UNAVAILABLE"


async def test_virustotal_looks_up_existing_report_by_padded_base64_id() -> None:
    url = "https://example.com/a?x=1"
    cache = _Redis()
    client = _HttpClient(
        get_response=_Response(
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 4,
                            "harmless": 20,
                            "suspicious": 1,
                        }
                    }
                }
            }
        )
    )
    result = await threat_feeds.lookup_virustotal(
        url,
        redis_client=cache,  # type: ignore[arg-type]
        http_client=client,  # type: ignore[arg-type]
        settings=_settings(vt_api_key="test-key"),
        now=120,
    )
    expected_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    assert client.get_calls[0][0].endswith(f"/urls/{expected_id}")
    assert client.get_calls[0][1] == {"x-apikey": "test-key"}
    assert result.status == "MATCH"
    assert result.indicators[0].severity == "medium"
    assert result.indicators[0].evidence == {
        "malicious_vendors": 4,
        "total_vendors": 25,
    }
    assert cache.eval_calls


async def test_virustotal_404_means_no_existing_report() -> None:
    result = await threat_feeds.lookup_virustotal(
        "https://example.com",
        redis_client=_Redis(),  # type: ignore[arg-type]
        http_client=_HttpClient(get_response=_Response({}, status_code=404)),  # type: ignore[arg-type]
        settings=_settings(vt_api_key="test-key"),
        now=120,
    )
    assert result.status == "NO_REPORT"
    assert result.indicators == []


async def test_virustotal_limiter_blocks_lookup_when_quota_exhausted() -> None:
    cache = _Redis()
    cache.allow_vt = False
    client = _HttpClient()
    result = await threat_feeds.lookup_virustotal(
        "https://example.com",
        redis_client=cache,  # type: ignore[arg-type]
        http_client=client,  # type: ignore[arg-type]
        settings=_settings(vt_api_key="test-key"),
        now=180,
    )
    assert result.status == "UNAVAILABLE"
    assert "rate limit" in result.indicators[0].message
    assert not client.get_calls


async def test_virustotal_timeout_is_unavailable() -> None:
    class _TimeoutClient(_HttpClient):
        async def get(self, *args, **kwargs):
            raise httpx.TimeoutException("timeout")

    result = await threat_feeds.lookup_virustotal(
        "https://example.com",
        redis_client=_Redis(),  # type: ignore[arg-type]
        http_client=_TimeoutClient(),  # type: ignore[arg-type]
        settings=_settings(vt_api_key="test-key"),
        now=180,
    )
    assert result.status == "UNAVAILABLE"


async def test_virustotal_limiter_failure_does_not_call_api() -> None:
    class _BrokenRedis(_Redis):
        async def eval(self, script: str, numkeys: int, *keys: str) -> int:
            raise OSError("redis unavailable")

    client = _HttpClient()
    result = await threat_feeds.lookup_virustotal(
        "https://example.com",
        redis_client=_BrokenRedis(),  # type: ignore[arg-type]
        http_client=client,  # type: ignore[arg-type]
        settings=_settings(vt_api_key="test-key"),
        now=180,
    )
    assert result.status == "UNAVAILABLE"
    assert not client.get_calls


async def test_feed_http_error_degrades_without_raising() -> None:
    client = _HttpClient(get_response=_Response({}, status_code=503))
    result = await threat_feeds.lookup_virustotal(
        "https://example.com",
        redis_client=_Redis(),  # type: ignore[arg-type]
        http_client=client,  # type: ignore[arg-type]
        settings=_settings(vt_api_key="test-key"),
        now=180,
    )
    assert result.status == "UNAVAILABLE"


@pytest.mark.parametrize(
    ("malicious", "expected"),
    [(0, "NO_MATCH"), (1, "low"), (3, "medium"), (6, "high")],
)
def test_virustotal_severity_scales_with_vendor_count(
    malicious: int, expected: str
) -> None:
    result = threat_feeds._virustotal_result(malicious, 10)
    if malicious == 0:
        assert result.status == expected
        assert not result.indicators
    else:
        assert result.indicators[0].severity == expected
