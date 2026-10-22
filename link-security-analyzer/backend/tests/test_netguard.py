"""Network-target validation tests; DNS answers are provided by fakes."""

import ipaddress

import dns.resolver
import pytest

from app.config import Settings
from app.core.netguard import BlockedTargetError, assert_public_target


class _Record:
    def __init__(self, address: str) -> None:
        self.address = address


class _Resolver:
    def __init__(self, answers: dict[tuple[str, str], list[str]]) -> None:
        self.answers = answers

    async def resolve(self, hostname: str, record_type: str, *, lifetime: float):
        records = self.answers.get((hostname, record_type), [])
        if not records:
            raise dns.resolver.NoAnswer
        return [_Record(address) for address in records]


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1",
        "10.1.2.3",
        "http://172.16.0.1",
        "192.168.1.20",
        "https://[::1]",
        "0x7f000001",
        "2130706433",
        "0177.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "https://[::ffff:127.0.0.1]",
        "http://224.0.0.1",
        "http://0.0.0.0",
    ],
)
async def test_blocks_non_public_ip_forms(target: str) -> None:
    with pytest.raises(BlockedTargetError) as error:
        await assert_public_target(target)
    assert error.value.reason_code == "NON_PUBLIC_ADDRESS"


@pytest.mark.parametrize(
    "target",
    [
        "localhost",
        "service.localhost",
        "app.internal",
        "db.local",
        "redis",
        "postgres",
        "backend",
        "worker",
    ],
)
async def test_blocks_denied_hostnames_before_dns(target: str) -> None:
    with pytest.raises(BlockedTargetError) as error:
        await assert_public_target(target)
    assert error.value.reason_code == "DENIED_HOSTNAME"


async def test_denylist_can_be_extended_by_configuration() -> None:
    settings = Settings(_env_file=None, netguard_denylist="localhost,custom-service")
    with pytest.raises(BlockedTargetError) as error:
        await assert_public_target("custom-service", settings=settings)
    assert error.value.reason_code == "DENIED_HOSTNAME"


@pytest.mark.parametrize("target", ["ftp://example.com", "file:///etc/passwd"])
async def test_rejects_non_web_schemes(target: str) -> None:
    with pytest.raises(BlockedTargetError) as error:
        await assert_public_target(target)
    assert error.value.reason_code == "UNSUPPORTED_SCHEME"


@pytest.mark.parametrize(
    "target", ["", "https://user:pass@example.com", "https://example.com:99999"]
)
async def test_rejects_malformed_targets(target: str) -> None:
    with pytest.raises(BlockedTargetError) as error:
        await assert_public_target(target)
    assert error.value.reason_code == "INVALID_TARGET"


async def test_blocks_hostname_if_any_dns_answer_is_private() -> None:
    resolver = _Resolver(
        {
            ("redirect.example", "A"): ["8.8.8.8", "192.168.0.10"],
            ("redirect.example", "AAAA"): ["2606:4700:4700::1111"],
        }
    )
    with pytest.raises(BlockedTargetError) as error:
        await assert_public_target("redirect.example", resolver=resolver)  # type: ignore[arg-type]
    assert error.value.reason_code == "NON_PUBLIC_ADDRESS"


async def test_blocks_hostname_that_resolves_only_to_private_ip() -> None:
    resolver = _Resolver({("private.example", "A"): ["10.0.0.8"]})
    with pytest.raises(BlockedTargetError) as error:
        await assert_public_target("private.example", resolver=resolver)  # type: ignore[arg-type]
    assert error.value.reason_code == "NON_PUBLIC_ADDRESS"


async def test_blocks_hostname_that_has_no_dns_answers() -> None:
    resolver = _Resolver({})
    with pytest.raises(BlockedTargetError) as error:
        await assert_public_target(
            "missing.example",
            resolver=resolver,  # type: ignore[arg-type]
        )
    assert error.value.reason_code == "DNS_RESOLUTION_FAILED"


async def test_blocks_target_if_either_dns_family_times_out() -> None:
    class _TimeoutResolver(_Resolver):
        async def resolve(self, hostname: str, record_type: str, *, lifetime: float):
            if record_type == "AAAA":
                raise dns.exception.Timeout
            return [_Record("8.8.8.8")]

    with pytest.raises(BlockedTargetError) as error:
        await assert_public_target(
            "mixed.example",
            resolver=_TimeoutResolver({}),  # type: ignore[arg-type]
        )
    assert error.value.reason_code == "DNS_RESOLUTION_FAILED"


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("8.8.8.8", "8.8.8.8"),
        ("https://[2606:4700:4700::1111]/", "2606:4700:4700::1111"),
    ],
)
async def test_allows_public_ip_literals(target: str, expected: str) -> None:
    result = await assert_public_target(target)
    assert result.addresses == (str(ipaddress.ip_address(expected)),)


async def test_resolves_and_allows_public_dns_answers() -> None:
    resolver = _Resolver(
        {
            ("example.com", "A"): ["93.184.216.34"],
            ("example.com", "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
        }
    )
    result = await assert_public_target(
        "https://Example.com/path",
        resolver=resolver,  # type: ignore[arg-type]
    )
    assert result.hostname == "example.com"
    assert len(result.addresses) == 2
    assert result.port == 443
