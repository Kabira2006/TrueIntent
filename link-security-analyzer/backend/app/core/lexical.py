"""Lexical URL analysis: offline, fast feature extraction and Stage 1 signals.

Everything here is computed from the URL string only - no network, no DNS, no
external lookups.  Signal ids and point weights follow spec sections 8 (Stage 1)
and 9.  Weights are starting values and are tuned in Phase 8.
"""

from __future__ import annotations

import re
from ipaddress import ip_address
from typing import Any

from app.core._util import (
    _entropy,
)
from app.core.brands import (
    BrandCatalog,
    brand_in_subdomain_or_path,
    is_official,
    typosquat_match,
)
from app.core.router import RoutedInput

#: Risky TLDs (low weight; many legitimate sites use them).
RISKY_TLDS = frozenset(
    {
        "xyz",
        "top",
        "click",
        "live",
        "icu",
        "buzz",
        "shop",
        "online",
        "site",
        "work",
        "zip",
        "mov",
        "loan",
        "win",
        "bid",
        "review",
        "country",
        "kim",
        "party",
        "stream",
        "racing",
        "download",
        "fit",
        "gq",
        "cf",
        "ml",
        "ga",
        "tk",
    }
)

#: Common URL shorteners whose final destination is unknown until sandboxed.
SHORTENERS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "cutt.ly",
        "rb.gy",
        "is.gd",
        "goo.gl",
        "ow.ly",
        "bitly.com",
        "rebrand.ly",
        "tiny.cc",
        "tr.im",
        "cli.re",
    }
)

#: Sensitive keywords that hint at credential/payment harvesting in a host.
SENSITIVE_KEYWORDS = frozenset(
    {
        "login",
        "verify",
        "secure",
        "update",
        "kyc",
        "refund",
        "reward",
        "claim",
        "wallet",
        "suspend",
        "signin",
        "sign-in",
        "account",
        "banking",
        "payment",
        "pay",
    }
)


def _has_ip_host(host: str) -> bool:
    """True if the host is an IPv4/IPv6 literal or an obfuscated IP (decimal/hex/octal)."""
    try:
        ip_address(host)
        return True
    except ValueError:
        pass
    stripped = host.strip("[]")
    parts = stripped.split(".")
    if len(parts) == 4 and all(
        re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|0[0-7]+|[0-9]+)", p) for p in parts
    ):
        try:
            values = [int(p, 0) for p in parts]
            if all(0 <= v <= 255 for v in values):
                return True
        except ValueError:
            return False
    return False


def _keyword_count(text: str) -> int:
    lowered = text.lower()
    return sum(1 for keyword in SENSITIVE_KEYWORDS if keyword in lowered)


class LexicalResult(dict):
    """A numeric feature dict plus Stage 1 signals."""

    def __init__(self, features: dict[str, Any], signals: list[dict[str, Any]]) -> None:
        super().__init__(features)
        self["signals"] = signals
        self.features = features
        self.signals = signals


def analyze_url(
    routed: RoutedInput, catalog: BrandCatalog | None = None
) -> LexicalResult:
    """Produce numeric features and Stage 1 signals from a routed input."""
    features: dict[str, Any] = {}
    signals: list[dict[str, Any]] = []

    raw_input = routed.normalized_payload
    host = routed.host
    host_raw = host.raw if host else ""
    host_display = host.display if host else ""
    registrable = routed.registrable_domain or ""
    registrable_label = registrable.split(".")[0] if registrable else ""
    subdomains = (
        routed.host.raw.split(".")[:-2]
        if routed.host and "." in routed.host.raw
        else []
    )
    tld = registrable.split(".")[-1] if "." in registrable else ""
    scheme = (routed.scheme or "").lower()
    port = routed.port
    path = routed.path or ""
    query = routed.query or ""

    url_len = len(raw_input)
    host_len = len(host_raw)
    path_len = len(path)
    label_entropy = _entropy(registrable_label)
    digit_count = sum(c.isdigit() for c in host_raw)
    hyphen_count = host_raw.count("-")
    dot_count = host_raw.count(".")
    subdomain_count = len(subdomains)
    is_https = scheme == "https"
    port_nonstandard = port is not None and port not in (80, 443)
    is_shortener = (
        routed.registrable_domain in SHORTENERS if routed.registrable_domain else False
    )
    tld_risk_bucket = "risky" if tld in RISKY_TLDS else ("common" if tld else "none")

    features.update(
        {
            "url_len": url_len,
            "host_len": host_len,
            "path_len": path_len,
            "entropy": label_entropy,
            "shannon_entropy": label_entropy,
            "digit_count": digit_count,
            "hyphen_count": hyphen_count,
            "dot_count": dot_count,
            "subdomain_count": subdomain_count,
            "has_ip_host": _has_ip_host(host_raw),
            "has_at": "@" in raw_input,
            "has_punycode": bool(host and host.is_punycode),
            "tld": tld,
            "tld_risk_bucket": tld_risk_bucket,
            "is_https": is_https,
            "port_nonstandard": port_nonstandard,
            "keyword_counts": _keyword_count(host_raw + path + query),
            "is_shortener": is_shortener,
            "registrable_domain": registrable,
            "registrable_label": registrable_label,
        }
    )

    def add_signal(
        code: str, points: int, severity: str, explain: str, evidence: dict[str, Any]
    ) -> None:
        signals.append(
            {
                "id": code,
                "points": points,
                "severity": severity,
                "explain": explain,
                "evidence": evidence,
            }
        )

    # --- Stage 1 signals (spec section 8, Stage 1) ---
    if _has_ip_host(host_raw):
        add_signal(
            "IP_HOST",
            30,
            "high",
            "The address uses a raw IP address instead of a domain name.",
            {"host": host_raw, "display": host_display},
        )

    if host and host.is_punycode:
        add_signal(
            "PUNYCODE_HOST",
            25,
            "medium",
            "The domain uses punycode (xn--...) which can hide look-alike characters.",
            {"host": host_raw, "display": host_display},
        )

    if "@" in raw_input:
        add_signal(
            "AT_SYMBOL",
            20,
            "medium",
            "The address contains an @ in the authority part, a classic obfuscation trick.",
            {"evidence_key": "at_symbol"},
        )

    if is_shortener:
        add_signal(
            "SHORTENER",
            15,
            "medium",
            "The domain is a URL shortener; the real destination is hidden until the page is opened.",
            {"domain": routed.registrable_domain or ""},
        )

    if tld in RISKY_TLDS:
        add_signal(
            "SUSPICIOUS_TLD",
            5,
            "low",
            f"The top-level domain .{tld} is commonly abused, though many legitimate sites use it too.",
            {"tld": tld},
        )

    if subdomain_count >= 4:
        add_signal(
            "MANY_SUBDOMAINS",
            10,
            "low",
            f"The address uses {subdomain_count} subdomain labels, which can hide the real destination.",
            {"subdomain_count": subdomain_count},
        )

    if url_len > 100:
        add_signal(
            "LONG_URL",
            5,
            "info",
            f"The address is {url_len} characters long, longer than typical benign links.",
            {"url_len": url_len},
        )

    if label_entropy > 4.5 and len(registrable_label) >= 10:
        add_signal(
            "HIGH_ENTROPY_HOST",
            10,
            "low",
            "The domain label looks randomly generated (high entropy), typical of domain-generation algorithms.",
            {"host": host_raw, "entropy": round(label_entropy, 2)},
        )

    if hyphen_count >= 3 or (host_raw and digit_count / max(len(host_raw), 1) > 0.3):
        add_signal(
            "MANY_HYPHENS_DIGITS",
            10,
            "low",
            "The domain contains many hyphens or digits, often used in machine-generated look-alike domains.",
            {"hyphen_count": hyphen_count, "digit_count": digit_count},
        )

    keyword_count = _keyword_count(host_raw + path + query)
    if keyword_count:
        add_signal(
            "SENSITIVE_KEYWORDS",
            10,
            "low",
            "The address contains sensitive words (login, verify, KYC, refund, …) that scammers often use.",
            {"keyword_count": keyword_count},
        )

    if not is_https:
        add_signal(
            "NON_HTTPS",
            5,
            "low",
            "The link uses plain HTTP instead of HTTPS, so traffic is not encrypted.",
            {"scheme": scheme or "unknown"},
        )

    if port_nonstandard:
        add_signal(
            "NON_STANDARD_PORT",
            10,
            "low",
            f"The link uses a non-standard port ({port}).",
            {"port": port},
        )

    # --- Brand / typosquat signals (offline) ---
    if catalog is not None and registrable:
        official = is_official(registrable, catalog)
        if not official:
            match = typosquat_match(registrable_label, catalog)
            if match is not None:
                add_signal(
                    "TYPOSQUAT_BRAND",
                    35,
                    "high",
                    f"The address imitates {match.brand_display} but is not an official {match.brand_display} domain.",
                    {
                        "brand": match.brand_display,
                        "matched_label": match.matched_label,
                        "distance": match.distance,
                        "registrable_domain": registrable,
                    },
                )
            else:
                # Brand keyword appearing as a hyphen/dot-separated component of a
                # non-official domain (e.g. sbi-secure-login-verify.xyz).
                tokens = set(registrable_label.replace("-", ".").split("."))
                for brand in catalog.brands:
                    for keyword in brand.keywords:
                        if keyword and keyword in tokens:
                            add_signal(
                                "BRAND_IN_SUBDOMAIN",
                                25,
                                "high",
                                f"The address uses the {brand.display_name} name as a domain component on a non-official domain.",
                                {
                                    "brand": brand.id,
                                    "matched_keyword": keyword,
                                    "registrable_domain": registrable,
                                },
                            )
                            break
            subdomain_match = brand_in_subdomain_or_path(
                tuple(subdomains), path, catalog, registrable
            )
            if subdomain_match is not None:
                brand = catalog.brand(subdomain_match)
                add_signal(
                    "BRAND_IN_SUBDOMAIN",
                    25,
                    "high",
                    f"The address uses the {brand.display_name if brand else subdomain_match} name in a subdomain or path on a non-official domain.",
                    {"brand": subdomain_match, "registrable_domain": registrable},
                )

    return LexicalResult(features, signals)
