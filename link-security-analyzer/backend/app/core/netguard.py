"""Validate public network destinations before making outbound connections."""

import asyncio
import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.resolver
from pydantic import BaseModel, ConfigDict

from app.config import Settings, get_settings

_DENIED_REASON_CODES = Literal[
    "INVALID_TARGET",
    "UNSUPPORTED_SCHEME",
    "DENIED_HOSTNAME",
    "NON_PUBLIC_ADDRESS",
    "DNS_RESOLUTION_FAILED",
]
_NUMERIC_COMPONENT = re.compile(r"^(?:0[xX][0-9a-fA-F]+|[0-9]+)$")


class BlockedTargetError(ValueError):
    """A destination was rejected before a network connection was made."""

    def __init__(self, reason_code: _DENIED_REASON_CODES, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class ResolvedTarget(BaseModel):
    """A validated destination and every public address returned by DNS."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str
    addresses: tuple[str, ...]
    scheme: Literal["http", "https"]
    port: int


async def assert_public_target(
    url_or_host: str,
    *,
    settings: Settings | None = None,
    resolver: dns.asyncresolver.Resolver | None = None,
) -> ResolvedTarget:
    """Reject non-web, denied, or non-public targets before connecting."""
    current_settings = settings or get_settings()
    scheme, host, port = _parse_target(url_or_host)
    if scheme not in {"http", "https"}:
        raise BlockedTargetError(
            "UNSUPPORTED_SCHEME", "Only HTTP and HTTPS targets are allowed."
        )

    normalized_host = host.rstrip(".").lower()
    if _is_denied_hostname(normalized_host, current_settings):
        raise BlockedTargetError("DENIED_HOSTNAME", "The target hostname is denied.")

    literal_ip = _normalize_ip_literal(normalized_host)
    if literal_ip is not None:
        if _is_non_public(literal_ip):
            raise BlockedTargetError(
                "NON_PUBLIC_ADDRESS", "The target address is not publicly routable."
            )
        return ResolvedTarget(
            hostname=normalized_host,
            addresses=(str(literal_ip),),
            scheme=scheme,
            port=port,
        )

    dns_resolver = resolver or dns.asyncresolver.Resolver()
    answers = await asyncio.gather(
        _resolve_records(
            dns_resolver, normalized_host, "A", current_settings.dns_timeout_seconds
        ),
        _resolve_records(
            dns_resolver, normalized_host, "AAAA", current_settings.dns_timeout_seconds
        ),
        return_exceptions=True,
    )
    if any(isinstance(answer, asyncio.CancelledError) for answer in answers):
        raise asyncio.CancelledError
    if any(isinstance(answer, Exception) for answer in answers):
        raise BlockedTargetError(
            "DNS_RESOLUTION_FAILED",
            "The target hostname could not be checked across both address families.",
        )
    addresses = sorted(
        {
            address
            for answer in answers
            if isinstance(answer, list)
            for address in answer
        }
    )
    if not addresses:
        raise BlockedTargetError(
            "DNS_RESOLUTION_FAILED",
            "The target hostname did not resolve to an address.",
        )

    parsed_addresses = [ipaddress.ip_address(address) for address in addresses]
    if any(_is_non_public(address) for address in parsed_addresses):
        raise BlockedTargetError(
            "NON_PUBLIC_ADDRESS",
            "At least one target address is not publicly routable.",
        )

    return ResolvedTarget(
        hostname=normalized_host,
        addresses=tuple(str(address) for address in parsed_addresses),
        scheme=scheme,
        port=port,
    )


async def _resolve_records(
    resolver: dns.asyncresolver.Resolver,
    hostname: str,
    record_type: str,
    timeout: float,
) -> list[str]:
    try:
        answer = await resolver.resolve(hostname, record_type, lifetime=timeout)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    return [str(record.address) for record in answer]


def _parse_target(value: str) -> tuple[str, str, int]:
    if not isinstance(value, str) or not value.strip():
        raise BlockedTargetError(
            "INVALID_TARGET", "A non-empty URL or hostname is required."
        )

    raw = value.strip()
    if "://" not in raw:
        parsed = urlsplit(f"//{raw}", scheme="https")
        scheme = "https"
    else:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise BlockedTargetError(
            "UNSUPPORTED_SCHEME", "Only HTTP and HTTPS targets are allowed."
        )
    if parsed.username is not None or parsed.password is not None:
        raise BlockedTargetError(
            "INVALID_TARGET", "User information is not allowed in a target."
        )
    host = parsed.hostname
    if host is None or any(character.isspace() for character in host):
        raise BlockedTargetError("INVALID_TARGET", "The target hostname is invalid.")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as error:
        raise BlockedTargetError(
            "INVALID_TARGET", "The target port is invalid."
        ) from error
    if not 1 <= port <= 65535:
        raise BlockedTargetError("INVALID_TARGET", "The target port is invalid.")
    return scheme, host, port


def _is_denied_hostname(hostname: str, settings: Settings) -> bool:
    denied = {
        item.strip().lower().rstrip(".")
        for item in settings.netguard_denylist.split(",")
        if item.strip()
    }
    return hostname in denied or hostname.endswith(
        (".localhost", ".internal", ".local")
    )


def _normalize_ip_literal(
    hostname: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        pass

    components = hostname.split(".")
    if not components or not all(
        _NUMERIC_COMPONENT.fullmatch(part) for part in components
    ):
        return None
    if len(components) > 4:
        raise BlockedTargetError(
            "INVALID_TARGET", "The numeric IP address is malformed."
        )

    values = [_parse_numeric_component(component) for component in components]
    if any(value < 0 for value in values):
        raise BlockedTargetError(
            "INVALID_TARGET", "The numeric IP address is malformed."
        )
    if any(value > 255 for value in values[:-1]):
        raise BlockedTargetError(
            "INVALID_TARGET", "The numeric IP address is malformed."
        )

    remaining_bytes = 5 - len(values)
    if values[-1] >= 1 << (8 * remaining_bytes):
        raise BlockedTargetError(
            "INVALID_TARGET", "The numeric IP address is malformed."
        )
    address_value = values[-1]
    for index, value in enumerate(values[:-1]):
        address_value |= value << (8 * (3 - index))
    return ipaddress.IPv4Address(address_value)


def _parse_numeric_component(component: str) -> int:
    if component.lower().startswith("0x"):
        return int(component, 0)
    if len(component) > 1 and component.startswith("0"):
        if any(character not in "01234567" for character in component):
            raise BlockedTargetError(
                "INVALID_TARGET", "The numeric IP address is malformed."
            )
        return int(component, 8)
    return int(component, 10)


def _is_non_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return _is_non_public(address.ipv4_mapped)
    cgnat = ipaddress.ip_network("100.64.0.0/10")
    if isinstance(address, ipaddress.IPv4Address) and address in cgnat:
        return True
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    )
