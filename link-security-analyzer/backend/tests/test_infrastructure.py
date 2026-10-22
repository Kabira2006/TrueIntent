"""Domain registration and DNS tests with all external services mocked."""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from app.config import Settings
from app.core import infrastructure

_UTC = timezone.utc  # noqa: UP017 - local validation runtime is Python 3.10


class _Redis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def get(self, key: str):
        return self.values.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self.values[key] = value
        self.ttls[key] = ttl

    async def aclose(self) -> None:
        return None


class _Response:
    status_code = 200

    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self.payload


class _HttpClient:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.urls: list[str] = []

    async def get(self, url: str):
        self.urls.append(url)
        return self.response

    async def aclose(self) -> None:
        return None


class _DnsRecord:
    def __init__(self, value: str) -> None:
        self.address = value


class _DnsAnswer(list):
    def __init__(self, values: list[str], ttl: int) -> None:
        super().__init__(_DnsRecord(value) for value in values)
        self.rrset = SimpleNamespace(ttl=ttl)


class _DnsResolver:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses

    async def resolve(self, domain: str, record_type: str, *, lifetime: float):
        response = self.responses.get(record_type, dns.resolver.NoAnswer())
        if isinstance(response, BaseException):
            raise response
        return response


def _settings(**kwargs) -> Settings:
    return Settings(_env_file=None, **kwargs)


async def test_invalid_domain_is_unknown_without_repository_lookup() -> None:
    called = False

    async def repository(domain: str):
        nonlocal called
        called = True

    result = await infrastructure.get_domain_info(
        "example.com?key=not-a-domain",
        repository=repository,
        redis_client=_Redis(),  # type: ignore[arg-type]
    )
    assert result.status == "UNKNOWN"
    assert not called


async def test_uses_fresh_database_cache_before_rdap() -> None:
    now = datetime.now(_UTC)
    cached_record = SimpleNamespace(
        updated_at=now - timedelta(days=2),
        registered_at=now - timedelta(days=5),
        registrar="Example Registrar",
    )
    called = False

    async def repository(domain: str):
        nonlocal called
        called = domain == "example.com"
        return cached_record

    result = await infrastructure.get_domain_info(
        "Example.com",
        repository=repository,
        redis_client=_Redis(),  # type: ignore[arg-type]
    )
    assert called
    assert result.domain_age_days == 5
    assert result.indicators[0].code == "DOMAIN_VERY_NEW"


async def test_ignores_stale_database_record_then_uses_rdap() -> None:
    now = datetime.now(_UTC)
    stale_record = SimpleNamespace(
        updated_at=now - timedelta(days=8),
        registered_at=now - timedelta(days=100),
        registrar="Old Registrar",
    )

    async def repository(domain: str):
        return stale_record

    client = _HttpClient(
        _Response(
            {
                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": (now - timedelta(days=10)).isoformat(),
                    }
                ],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Privacy Proxy"]]],
                    }
                ],
            }
        )
    )
    result = await infrastructure.get_domain_info(
        "example.com",
        repository=repository,
        redis_client=_Redis(),  # type: ignore[arg-type]
        http_client=client,  # type: ignore[arg-type]
    )
    assert result.domain_age_days == 10
    assert {item.code for item in result.indicators} == {
        "DOMAIN_VERY_NEW",
        "REGISTRAR_PRIVACY_PROXY",
    }
    assert client.urls[0].startswith("https://")


async def test_rdap_and_whois_failure_returns_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FailingHttp:
        async def get(self, url: str):
            raise OSError("lookup failure")

        async def aclose(self) -> None:
            return None

    async def no_repository(domain: str):
        return None

    async def fail_whois(*args, **kwargs):
        raise OSError("whois failure")

    monkeypatch.setattr(infrastructure.asyncwhois, "aio_whois_domain", fail_whois)
    result = await infrastructure.get_domain_info(
        "example.com",
        repository=no_repository,
        redis_client=_Redis(),  # type: ignore[arg-type]
        http_client=_FailingHttp(),  # type: ignore[arg-type]
    )
    assert result.status == "UNKNOWN"
    assert result.domain_age_days is None
    assert result.indicators[0].code == "WHOIS_TIMEOUT_OR_UNAVAILABLE"


async def test_whois_fallback_extracts_registration_date_and_caches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registered = datetime.now(_UTC) - timedelta(days=120)

    async def whois_lookup(domain: str, *, timeout: int):
        assert domain == "example.com"
        assert timeout == 3
        return SimpleNamespace(
            parser_output={
                "creation_date": registered.isoformat(),
                "registrar": "Example Registrar",
            }
        )

    class _NoRdapHttp(_HttpClient):
        async def get(self, url: str):
            raise OSError("RDAP unavailable")

    async def no_repository(domain: str):
        return None

    monkeypatch.setattr(infrastructure.asyncwhois, "aio_whois_domain", whois_lookup)
    cache = _Redis()
    result = await infrastructure.get_domain_info(
        "example.com",
        repository=no_repository,
        redis_client=cache,  # type: ignore[arg-type]
        http_client=_NoRdapHttp(_Response({})),  # type: ignore[arg-type]
    )
    assert result.status == "KNOWN"
    assert result.domain_age_days >= 119
    assert not result.indicators
    assert next(iter(cache.ttls.values())) == 86400


async def test_domain_lookup_timeout_returns_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def slow_lookup(*args, **kwargs):
        await asyncio.sleep(1)

    async def no_repository(domain: str):
        return None

    monkeypatch.setattr(infrastructure, "_rdap_then_whois", slow_lookup)
    result = await infrastructure.get_domain_info(
        "example.com",
        repository=no_repository,
        redis_client=_Redis(),  # type: ignore[arg-type]
        http_client=_HttpClient(_Response({})),  # type: ignore[arg-type]
        settings=_settings(whois_timeout_seconds=0.01),
    )
    assert result.status == "UNKNOWN"
    assert result.indicators[0].code == "WHOIS_TIMEOUT_OR_UNAVAILABLE"


@pytest.mark.parametrize(
    ("age", "severity"),
    [(6, "high"), (7, "medium"), (29, "medium"), (30, "low"), (89, "low"), (90, None)],
)
def test_domain_age_severity_thresholds(age: int, severity: str | None) -> None:
    registered_at = datetime.now(_UTC) - timedelta(days=age)
    result = infrastructure._domain_info_from_registration(registered_at, None)
    new_domain = next(
        (item for item in result.indicators if item.code == "DOMAIN_VERY_NEW"),
        None,
    )
    assert (new_domain.severity if new_domain else None) == severity


async def test_dns_reports_missing_mail_and_fast_flux_like_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def public_target(*args, **kwargs):
        return None

    monkeypatch.setattr(infrastructure, "assert_public_target", public_target)
    resolver = _DnsResolver(
        {
            "A": _DnsAnswer(
                ["8.8.8.1", "8.8.8.2", "8.8.8.3", "8.8.8.4", "8.8.8.5"],
                30,
            ),
            "AAAA": _DnsAnswer(["2606:4700:4700::1111"], 120),
            "MX": dns.resolver.NoAnswer(),
            "NS": _DnsAnswer(["ns1.example.com"], 300),
        }
    )
    result = await infrastructure.resolve_dns(
        "example.com",
        resolver=resolver,
        settings=_settings(),  # type: ignore[arg-type]
    )
    assert result.status == "AVAILABLE"
    assert result.record_counts["A"] == 5
    assert {item.code for item in result.indicators} == {
        "NO_MX_RECORD",
        "FAST_FLUX_LIKE",
    }


async def test_dns_timeout_degrades_to_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def public_target(*args, **kwargs):
        return None

    monkeypatch.setattr(infrastructure, "assert_public_target", public_target)
    resolver = _DnsResolver(
        {
            record_type: dns.exception.Timeout
            for record_type in ("A", "AAAA", "MX", "NS")
        }
    )
    result = await infrastructure.resolve_dns(
        "example.com",
        resolver=resolver,
        settings=_settings(),  # type: ignore[arg-type]
    )
    assert result.status == "UNAVAILABLE"
    assert {item.code for item in result.indicators} == {"DNS_LOOKUP_UNAVAILABLE"}


async def test_dns_reports_missing_a_and_mx_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def public_target(*args, **kwargs):
        return None

    monkeypatch.setattr(infrastructure, "assert_public_target", public_target)
    resolver = _DnsResolver(
        {
            "A": dns.resolver.NoAnswer(),
            "AAAA": _DnsAnswer(["2606:4700:4700::1111"], 120),
            "MX": dns.resolver.NoAnswer(),
            "NS": _DnsAnswer(["ns1.example.com"], 300),
        }
    )
    result = await infrastructure.resolve_dns(
        "example.com",
        resolver=resolver,
        settings=_settings(),  # type: ignore[arg-type]
    )
    assert {item.code for item in result.indicators} == {"NO_A_RECORD", "NO_MX_RECORD"}


async def test_partial_dns_failures_are_reported_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def public_target(*args, **kwargs):
        return None

    monkeypatch.setattr(infrastructure, "assert_public_target", public_target)
    resolver = _DnsResolver(
        {
            "A": dns.exception.Timeout,
            "AAAA": _DnsAnswer(["2606:4700:4700::1111"], 120),
            "MX": dns.resolver.NoAnswer(),
            "NS": _DnsAnswer(["ns1.example.com"], 300),
        }
    )
    result = await infrastructure.resolve_dns(
        "example.com",
        resolver=resolver,  # type: ignore[arg-type]
        settings=_settings(),
    )
    assert result.status == "UNAVAILABLE"
    assert {item.code for item in result.indicators} == {
        "NO_MX_RECORD",
        "DNS_LOOKUP_UNAVAILABLE",
    }
