"""ML feature extraction for phishing detection.

Reuses lexical.py analysis and adds infrastructure/reputation features.
Designed for offline mode (cached/lexical only) for large batch evaluation.

Feature schema documented in feature_schema.json.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from app.core.brands import BrandCatalog
from app.core.input_router import classify_input
from app.core.lexical import analyze_url

logger = logging.getLogger(__name__)

# Feature schema path
SCHEMA_PATH = Path(__file__).parent / "feature_schema.json"

# TLD risk groups (from spec section 8, Stage 1)
RISKY_TLDS = frozenset({
    "xyz", "top", "click", "live", "icu", "buzz", "shop", "online",
    "site", "work", "zip", "mov", "loan", "win", "bid", "review",
    "country", "kim", "party", "stream", "racing", "download", "fit",
    "gq", "cf", "ml", "ga", "tk"
})

COMMON_TLDS = frozenset({
    "com", "org", "net", "edu", "gov", "co.in", "in", "co.uk", "de",
    "fr", "jp", "cn", "au", "ca", "io", "dev"
})


def extract_features(
    url: str,
    catalog: Optional[BrandCatalog] = None,
    infrastructure_data: Optional[dict[str, Any]] = None,
    offline_mode: bool = False,
) -> dict[str, Any]:
    """Extract numeric ML features from a URL.
    
    Args:
        url: The URL to analyze
        catalog: Brand catalog for typosquat detection (optional)
        infrastructure_data: Pre-computed infrastructure check results
            (domain_age_days, dns_resolves, mx_present, tls_age_days)
        offline_mode: If True, use only lexical features + cached infrastructure
    
    Returns:
        Feature dict with all numeric/boolean values.
        Includes 'missing_features' list for fields that couldn't be computed.
    """
    features: dict[str, Any] = {}
    missing = []

    # Classify and route input
    classified = classify_input(url)
    if classified.payload_type != "URL":
        # UPI/non-URL: return minimal features
        return {
            "url_len": len(url),
            "is_url": False,
            "missing_features": ["all_url_features"],
        }

    routed = classified  # Reuse RoutedInput
    
    # Extract lexical features (always available, offline)
    lexical_result = analyze_url(routed, catalog=catalog)
    lexical_features = lexical_result.features
    
    # Copy lexical features (host-level only to avoid path artefact)
    features.update({
        "url_len": lexical_features.get("url_len", 0),
        "host_len": lexical_features.get("host_len", 0),
        "entropy": lexical_features.get("entropy", 0.0),
        "digit_count": lexical_features.get("digit_count", 0),
        "hyphen_count": lexical_features.get("hyphen_count", 0),
        "dot_count": lexical_features.get("dot_count", 0),
        "subdomain_count": lexical_features.get("subdomain_count", 0),
        "has_ip_host": int(lexical_features.get("has_ip_host", False)),
        "has_at": int(lexical_features.get("has_at", False)),
        "has_punycode": int(lexical_features.get("has_punycode", False)),
        "is_https": int(lexical_features.get("is_https", False)),
        "port_nonstandard": int(lexical_features.get("port_nonstandard", False)),
        "keyword_counts": lexical_features.get("keyword_counts", 0),
        "is_shortener": int(lexical_features.get("is_shortener", False)),
    })
    
    # TLD risk bucket as numeric
    tld = lexical_features.get("tld", "")
    if tld in RISKY_TLDS:
        features["tld_risk"] = 2  # high risk
    elif tld in COMMON_TLDS:
        features["tld_risk"] = 0  # common/safe
    else:
        features["tld_risk"] = 1  # neutral
    
    # Brand/typosquat signals (from lexical signals)
    signals = lexical_result.signals
    features["has_typosquat_signal"] = int(
        any(s["id"] == "TYPOSQUAT_BRAND" for s in signals)
    )
    features["has_brand_in_subdomain"] = int(
        any(s["id"] == "BRAND_IN_SUBDOMAIN" for s in signals)
    )
    
    # Path features (marked separately for "optimistic" model variant)
    path_len = lexical_features.get("path_len", 0)
    features["path_len"] = path_len
    features["has_path"] = int(path_len > 1)  # "/" doesn't count
    
    # Infrastructure features (may be missing in offline mode)
    if infrastructure_data:
        # Domain age (nullable with missing indicator)
        domain_age = infrastructure_data.get("domain_age_days")
        if domain_age is not None:
            features["domain_age_days"] = domain_age
            features["domain_age_missing"] = 0
            features["domain_age_lt_30"] = int(domain_age < 30)
            features["domain_age_lt_90"] = int(domain_age < 90)
            features["domain_age_gt_365"] = int(domain_age >= 365)
        else:
            # Median imputation value (from typical distribution)
            features["domain_age_days"] = 730  # ~2 years
            features["domain_age_missing"] = 1
            features["domain_age_lt_30"] = 0
            features["domain_age_lt_90"] = 0
            features["domain_age_gt_365"] = 0
            missing.append("domain_age")
        
        # DNS resolution
        dns_resolves = infrastructure_data.get("dns_resolves")
        if dns_resolves is not None:
            features["dns_resolves"] = int(dns_resolves)
        else:
            features["dns_resolves"] = 1  # assume resolves
            missing.append("dns_resolves")
        
        # MX record present
        mx_present = infrastructure_data.get("mx_present")
        if mx_present is not None:
            features["mx_present"] = int(mx_present)
        else:
            features["mx_present"] = 0  # assume no MX
            missing.append("mx_present")
        
        # TLS certificate age
        tls_age = infrastructure_data.get("tls_age_days")
        if tls_age is not None:
            features["tls_age_days"] = tls_age
            features["tls_age_missing"] = 0
            features["tls_age_lt_7"] = int(tls_age < 7)
        else:
            features["tls_age_days"] = 365  # assume mature cert
            features["tls_age_missing"] = 1
            features["tls_age_lt_7"] = 0
            missing.append("tls_age")
    else:
        # No infrastructure data provided: mark all as missing
        features.update({
            "domain_age_days": 730,
            "domain_age_missing": 1,
            "domain_age_lt_30": 0,
            "domain_age_lt_90": 0,
            "domain_age_gt_365": 0,
            "dns_resolves": 1,
            "mx_present": 0,
            "tls_age_days": 365,
            "tls_age_missing": 1,
            "tls_age_lt_7": 0,
        })
        missing.extend(["domain_age", "dns_resolves", "mx_present", "tls_age"])
    
    # Offline mode flag
    features["offline_mode"] = int(offline_mode)
    features["missing_features"] = missing
    
    return features


def load_feature_schema() -> dict[str, Any]:
    """Load feature schema from JSON."""
    if SCHEMA_PATH.exists():
        with open(SCHEMA_PATH) as f:
            return json.load(f)
    return {}


def save_feature_schema(features: dict[str, Any]) -> None:
    """Save feature schema to JSON (for documentation)."""
    schema = {
        "version": "1.0",
        "description": "ML feature schema for phishing detection",
        "features": {},
    }
    
    for key, value in features.items():
        if key == "missing_features":
            continue
        dtype = type(value).__name__
        if dtype == "bool":
            dtype = "int"  # booleans converted to 0/1
        schema["features"][key] = {
            "dtype": dtype,
            "description": _feature_description(key),
        }
    
    with open(SCHEMA_PATH, "w") as f:
        json.dump(schema, f, indent=2)
    
    logger.info(f"Saved feature schema to {SCHEMA_PATH}")


def _feature_description(key: str) -> str:
    """Generate human-readable feature description."""
    descriptions = {
        "url_len": "Total URL length in characters",
        "host_len": "Hostname length",
        "entropy": "Shannon entropy of registrable domain label",
        "digit_count": "Number of digits in hostname",
        "hyphen_count": "Number of hyphens in hostname",
        "dot_count": "Number of dots in hostname",
        "subdomain_count": "Number of subdomain labels",
        "has_ip_host": "1 if host is IP address, 0 otherwise",
        "has_at": "1 if URL contains @ symbol, 0 otherwise",
        "has_punycode": "1 if domain uses punycode (xn--), 0 otherwise",
        "is_https": "1 if HTTPS, 0 if HTTP or other",
        "port_nonstandard": "1 if port is not 80/443, 0 otherwise",
        "keyword_counts": "Count of sensitive keywords (login, verify, etc.)",
        "is_shortener": "1 if domain is known URL shortener, 0 otherwise",
        "tld_risk": "TLD risk category: 0=common, 1=neutral, 2=risky",
        "has_typosquat_signal": "1 if typosquat brand match detected, 0 otherwise",
        "has_brand_in_subdomain": "1 if brand keyword in subdomain, 0 otherwise",
        "path_len": "Path length (for optimistic model only)",
        "has_path": "1 if path present, 0 otherwise (for optimistic model)",
        "domain_age_days": "Domain age in days (imputed if missing)",
        "domain_age_missing": "1 if domain age unavailable, 0 otherwise",
        "domain_age_lt_30": "1 if domain < 30 days old, 0 otherwise",
        "domain_age_lt_90": "1 if domain < 90 days old, 0 otherwise",
        "domain_age_gt_365": "1 if domain >= 1 year old, 0 otherwise",
        "dns_resolves": "1 if DNS resolution succeeded, 0 otherwise",
        "mx_present": "1 if MX record exists, 0 otherwise",
        "tls_age_days": "TLS certificate age in days (imputed if missing)",
        "tls_age_missing": "1 if TLS age unavailable, 0 otherwise",
        "tls_age_lt_7": "1 if TLS cert < 7 days old, 0 otherwise",
        "offline_mode": "1 if extracted in offline mode, 0 otherwise",
    }
    return descriptions.get(key, "")


# Feature columns for model training (host-level only, no path artefact)
FEATURE_COLUMNS_HOST_ONLY = [
    "url_len",
    "host_len",
    "entropy",
    "digit_count",
    "hyphen_count",
    "dot_count",
    "subdomain_count",
    "has_ip_host",
    "has_at",
    "has_punycode",
    "is_https",
    "port_nonstandard",
    "keyword_counts",
    "is_shortener",
    "tld_risk",
    "has_typosquat_signal",
    "has_brand_in_subdomain",
    "domain_age_days",
    "domain_age_missing",
    "domain_age_lt_30",
    "domain_age_lt_90",
    "domain_age_gt_365",
    "dns_resolves",
    "mx_present",
    "tls_age_days",
    "tls_age_missing",
    "tls_age_lt_7",
]

# Feature columns including path (optimistic model, higher leakage risk)
FEATURE_COLUMNS_WITH_PATH = FEATURE_COLUMNS_HOST_ONLY + [
    "path_len",
    "has_path",
]
