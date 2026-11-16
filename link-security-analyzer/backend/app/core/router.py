"""Input router: classify, normalize, and decompose pasted input.

Pure offline logic: trim invisible/control characters, enforce the 2048 cap,
classify URL / UPI deep link / bare domain / QR text / invalid, and compute
the registrable domain (eTLD+1) using tldextract with the Public Suffix List.
Suffix list URLs are disabled so no network call is made at runtime; tldextract
ships with a bundled copy of the Public Suffix List.

Every host is kept in two forms: the raw (as-typed) form used for analysis and
a decoded IDNA form used only for display, so punycode homographs are visible
to analysts while the raw form drives detection.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import SplitResult, urlsplit, urlunsplit

import tldextract
from pydantic import BaseModel, ConfigDict

from app.core.models import InputClassification

MAX_INPUT_LENGTH = 2048
_SUFFIX_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# Shared-hosting / platform suffixes: a registrable domain under these is a
# tenant site, not the platform itself, so it never gets popularity credit and
# each subdomain is treated as its own site.
SHARED_HOSTING_SUFFIXES = frozenset(
    {
        "github.io",
        "github.com",
        "gitlab.io",
        "vercel.app",
        "netlify.app",
        "pages.dev",
        "web.app",
        "firebaseapp.com",
        "herokuapp.com",
        "weebly.com",
        "wixsite.com",
        "blogspot.com",
        "blogspot.in",
        "wordpress.com",
        "square.site",
        "shopify.com",
        "surge.sh",
    }
)


class PayloadType(str):
    URL = "URL"
    UPI_DEEP_LINK = "UPI_DEEP_LINK"
    QR_TEXT = "QR_TEXT"


@dataclass(frozen=True)
class NormalizedHost:
    """A host in both its raw (analysis) and decoded (display) forms."""

    raw: str
    display: str
    is_punycode: bool


@dataclass(frozen=True)
class RoutedInput:
    """The fully decomposed result of routing one pasted input."""

    payload_type: str
    normalized_payload: str
    embedded_payload: str | None
    recognized: bool
    scheme: str | None
    host: NormalizedHost | None
    port: int | None
    path: str
    query: str
    fragment: str
    registrable_domain: str | None
    is_shared_hosting: bool


class RouteResult(BaseModel):
    """Serialisable router output shared with the rest of the pipeline."""

    model_config = ConfigDict(extra="forbid")

    payload_type: str
    normalized_payload: str
    embedded_payload: str | None = None
    recognized: bool = False
    scheme: str | None = None
    host: str | None = None
    host_display: str | None = None
    is_punycode: bool = False
    port: int | None = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    registrable_domain: str | None = None
    is_shared_hosting: bool = False


_ZERO_WIDTH_CHARACTERS = frozenset(
    {
        "\u034f",
        "\u061c",
        "\u115f",
        "\u1160",
        "\u17b4",
        "\u17b5",
        "\u180e",
        "\u200b",
        "\u200c",
        "\u200d",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2060",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
        "\ufeff",
    }
)

_EMBEDDED_LINK = re.compile(r"(?i)\b(?:https?://|upi://)[^\s<>\"']+")
_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _strip_invisible_characters(value: str) -> str:
    return "".join(
        character
        for character in value
        if unicodedata.category(character) != "Cc"
        and character not in _ZERO_WIDTH_CHARACTERS
    )


def _safe_urlsplit(value: str) -> SplitResult | None:
    try:
        return urlsplit(value)
    except ValueError:
        return None


def _normalize_scheme(value: str, scheme: str) -> str:
    return f"{scheme}:{value.split(':', maxsplit=1)[1]}"


def _decode_idna(host: str) -> str:
    """Return the Unicode display form of an IDNA/punycode host, else unchanged."""
    labels = []
    for label in host.split("."):
        if label.lower().startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
            except (UnicodeError, ValueError):
                labels.append(label)
        else:
            labels.append(label)
    return ".".join(labels)


def _is_bare_web_url(value: str, parsed: SplitResult | None) -> bool:
    if parsed is not None and parsed.scheme.lower() in {"http", "https"}:
        try:
            port = parsed.port
        except ValueError:
            return False
        return (port is None or 0 <= port <= 65535) and _is_valid_host(
            parsed.hostname, require_suffix=False
        )
    if "://" in value or any(character.isspace() for character in value):
        return False
    host = (
        value.split("/", maxsplit=1)[0]
        .split("?", maxsplit=1)[0]
        .split("#", maxsplit=1)[0]
    )
    if "@" in host:
        host = host.rsplit("@", maxsplit=1)[1]
    if ":" in host:
        host = host.split(":", maxsplit=1)[0]
    return _is_valid_host(host, require_suffix=True) and len(host.split(".")[-1]) >= 2


def _is_valid_host(host: str | None, *, require_suffix: bool) -> bool:
    if not host or any(character.isspace() for character in host):
        return False
    try:
        ip_address(host)
        return True
    except ValueError:
        labels = host.rstrip(".").split(".")
        return (not require_suffix or len(labels) >= 2) and all(
            _DOMAIN_LABEL.fullmatch(label) for label in labels
        )


def _has_domain_host(netloc: str) -> bool:
    if not netloc or "@" in netloc:
        return False
    host = netloc.rsplit("@", maxsplit=1)[-1].split(":", maxsplit=1)[0].rstrip(".")
    labels = host.split(".")
    return _is_valid_host(host, require_suffix=True) and len(labels[-1]) >= 2


def _normalize_web_url(value: str, parsed: SplitResult) -> str:
    if parsed.scheme.lower() not in {"http", "https"}:
        return value
    host = parsed.hostname
    if host is None:
        return value
    user_info = ""
    if parsed.username is not None:
        user_info = parsed.username
        if parsed.password is not None:
            user_info += f":{parsed.password}"
        user_info += "@"
    normalized_host = host.lower()
    if ":" in normalized_host:
        normalized_host = f"[{normalized_host}]"
    netloc = f"{user_info}{normalized_host}"
    try:
        port = parsed.port
    except ValueError:
        return value
    if port is not None:
        netloc += f":{port}"
    return urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path, parsed.query, parsed.fragment)
    )


def _registrable_domain(host: str) -> str:
    """Compute eTLD+1 for a host using the bundled Public Suffix List.

    Shared-hosting platforms (github.io, vercel.app, …) return their platform
    domain as the registrable domain; callers treat those specially so tenant
    subdomains stay distinct sites.
    """
    extracted = _SUFFIX_EXTRACTOR(host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return host.lower()


def classify_and_route(raw: str) -> RoutedInput:
    """Classify and decompose one pasted input into a :class:`RoutedInput`."""
    if not isinstance(raw, str):
        raise TypeError("raw input must be a string")
    trimmed = raw.strip()
    if not trimmed:
        raise ValueError("input must not be empty")
    if len(trimmed) > MAX_INPUT_LENGTH:
        raise ValueError(f"input must be no longer than {MAX_INPUT_LENGTH} characters")

    normalized = _strip_invisible_characters(trimmed).strip()
    if not normalized:
        raise ValueError("input must not be empty")

    parsed = _safe_urlsplit(normalized)
    scheme = parsed.scheme.lower() if parsed and parsed.scheme else None

    if scheme == "upi":
        host = _host_parts(parsed.hostname) if parsed and parsed.hostname else None
        return RoutedInput(
            payload_type="UPI_DEEP_LINK",
            normalized_payload=_normalize_scheme(normalized, "upi"),
            embedded_payload=None,
            recognized=True,
            scheme="upi",
            host=host,
            port=parsed.port,
            path=parsed.path,
            query=parsed.query,
            fragment=parsed.fragment,
            registrable_domain=_registrable_domain(parsed.hostname)
            if parsed and parsed.hostname
            else None,
            is_shared_hosting=False,
        )

    if _is_bare_web_url(normalized, parsed):
        host = _host_parts(parsed.hostname) if parsed and parsed.hostname else None
        registrable = (
            _registrable_domain(parsed.hostname) if parsed and parsed.hostname else None
        )
        return RoutedInput(
            payload_type="URL",
            normalized_payload=_normalize_web_url(normalized, parsed),
            embedded_payload=None,
            recognized=True,
            scheme="https" if not scheme else scheme,
            host=host,
            port=parsed.port,
            path=parsed.path,
            query=parsed.query,
            fragment=parsed.fragment,
            registrable_domain=registrable,
            is_shared_hosting=registrable in SHARED_HOSTING_SUFFIXES
            if registrable
            else False,
        )

    match = _EMBEDDED_LINK.search(normalized)
    if match is not None:
        embedded = match.group(0).rstrip(".,;:!?)]}")
        embedded_parts = _safe_urlsplit(embedded)
        if embedded_parts is not None and embedded_parts.scheme.lower() == "upi":
            embedded = _normalize_scheme(embedded, "upi")
            return RoutedInput(
                payload_type="QR_TEXT",
                normalized_payload=normalized,
                embedded_payload=embedded,
                recognized=True,
                scheme="upi",
                host=_host_parts(embedded_parts.hostname)
                if embedded_parts and embedded_parts.hostname
                else None,
                port=embedded_parts.port,
                path=embedded_parts.path,
                query=embedded_parts.query,
                fragment=embedded_parts.fragment,
                registrable_domain=_registrable_domain(embedded_parts.hostname)
                if embedded_parts and embedded_parts.hostname
                else None,
                is_shared_hosting=False,
            )
        if embedded_parts is not None:
            embedded = _normalize_web_url(embedded, embedded_parts)
            host = (
                _host_parts(embedded_parts.hostname)
                if embedded_parts.hostname
                else None
            )
            registrable = (
                _registrable_domain(embedded_parts.hostname)
                if embedded_parts and embedded_parts.hostname
                else None
            )
            return RoutedInput(
                payload_type="QR_TEXT",
                normalized_payload=normalized,
                embedded_payload=embedded,
                recognized=True,
                scheme=embedded_parts.scheme.lower(),
                host=host,
                port=embedded_parts.port,
                path=embedded_parts.path,
                query=embedded_parts.query,
                fragment=embedded_parts.fragment,
                registrable_domain=registrable,
                is_shared_hosting=registrable in SHARED_HOSTING_SUFFIXES
                if registrable
                else False,
            )

    return RoutedInput(
        payload_type="QR_TEXT",
        normalized_payload=normalized,
        embedded_payload=None,
        recognized=False,
        scheme=scheme,
        host=None,
        port=None,
        path=parsed.path if parsed else "",
        query=parsed.query if parsed else "",
        fragment=parsed.fragment if parsed else "",
        registrable_domain=None,
        is_shared_hosting=False,
    )


def _host_parts(host: str | None) -> NormalizedHost | None:
    if not host:
        return None
    raw = host.lower()
    is_punycode = any(label.startswith("xn--") for label in raw.split("."))
    return NormalizedHost(raw=raw, display=_decode_idna(raw), is_punycode=is_punycode)


def route_to_model(raw: str) -> RouteResult:
    """Convenience: route and return a serialisable :class:`RouteResult`."""
    routed = classify_and_route(raw)
    return RouteResult(
        payload_type=routed.payload_type,
        normalized_payload=routed.normalized_payload,
        embedded_payload=routed.embedded_payload,
        recognized=routed.recognized,
        scheme=routed.scheme,
        host=routed.host.raw if routed.host else None,
        host_display=routed.host.display if routed.host else None,
        is_punycode=routed.host.is_punycode if routed.host else False,
        port=routed.port,
        path=routed.path,
        query=routed.query,
        fragment=routed.fragment,
        registrable_domain=routed.registrable_domain,
        is_shared_hosting=routed.is_shared_hosting,
    )


def to_classification(routed: RoutedInput) -> InputClassification:
    """Convert a :class:`RoutedInput` into the legacy :class:`InputClassification`."""
    return InputClassification(
        payload_type=routed.payload_type,  # type: ignore[arg-type]
        normalized_payload=routed.normalized_payload,
        embedded_payload=routed.embedded_payload,
        recognized=routed.recognized,
    )
