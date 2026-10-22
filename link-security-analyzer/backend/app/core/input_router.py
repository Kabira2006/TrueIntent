"""Classify pasted links and QR text without making network requests."""

import re
import unicodedata
from ipaddress import ip_address
from urllib.parse import SplitResult, urlsplit, urlunsplit

from app.core.models import InputClassification

MAX_INPUT_LENGTH = 2048
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


def classify_input(raw: str) -> InputClassification:
    """Classify a URL, UPI deep link, or QR text containing optional links."""
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
    if parsed is not None and parsed.scheme.lower() == "upi":
        return InputClassification(
            payload_type="UPI_DEEP_LINK",
            normalized_payload=_normalize_scheme(normalized, "upi"),
            recognized=True,
        )

    if _is_bare_web_url(normalized, parsed):
        return InputClassification(
            payload_type="URL",
            normalized_payload=_normalize_web_url(normalized, parsed),
            recognized=True,
        )

    match = _EMBEDDED_LINK.search(normalized)
    if match is not None:
        embedded = match.group(0).rstrip(".,;:!?)]}")
        embedded_parts = _safe_urlsplit(embedded)
        if embedded_parts is not None and embedded_parts.scheme.lower() == "upi":
            embedded = _normalize_scheme(embedded, "upi")
        elif embedded_parts is not None:
            embedded = _normalize_web_url(embedded, embedded_parts)
        return InputClassification(
            payload_type="QR_TEXT",
            normalized_payload=normalized,
            embedded_payload=embedded,
            recognized=True,
        )

    return InputClassification(
        payload_type="QR_TEXT",
        normalized_payload=normalized,
        recognized=False,
    )


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
    return _has_domain_host(host)


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
