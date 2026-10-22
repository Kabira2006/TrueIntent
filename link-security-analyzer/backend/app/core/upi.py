"""Extract explainable UPI-link indicators without contacting external systems."""

import json
import math
import re
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from pathlib import Path
from urllib.parse import SplitResult, parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict

from app.core.models import Indicator, UpiResult

_VPA_PATTERN = re.compile(r"^[A-Za-z0-9.\-_]{2,256}@[A-Za-z]{2,64}$")
_SUSPICIOUS_NOTE_WORDS = re.compile(
    r"\b(?:urgent|refund|kyc|verify|expire|blocked)\b", re.IGNORECASE
)
_UPI_CONFIG_PATH = Path(__file__).resolve().parents[2] / "data" / "upi_handles.json"
_FEATURE_NAMES = (
    "payee_vpa",
    "payee_name",
    "amount",
    "transaction_ref",
    "note",
    "currency",
    "mode",
    "merchant_code",
)


class _AmountThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    medium: Decimal
    high: Decimal


class _UpiConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    known_handles: list[str]
    brand_keywords: list[str]
    authority_words: list[str]
    amount_thresholds: _AmountThresholds


@lru_cache(maxsize=1)
def _load_config() -> _UpiConfig:
    with _UPI_CONFIG_PATH.open(encoding="utf-8") as config_file:
        return _UpiConfig.model_validate(json.load(config_file))


def analyze_upi(payload: str) -> UpiResult:
    """Parse UPI fields and report link-level facts, never user intent."""
    if not isinstance(payload, str):
        raise TypeError("UPI payload must be a string")

    stripped_payload = payload.strip()
    parsed = _safe_urlsplit(stripped_payload)
    if parsed is None:
        return _malformed_result("The link could not be parsed as a URI.")

    if parsed.scheme.lower() in {"http", "https"}:
        return _analyze_web_url(parsed)
    if parsed.scheme.lower() != "upi":
        return _malformed_result("The link does not use a UPI or web URL scheme.")

    action = _upi_action(parsed)
    if action not in {"pay", "collect", "mandate"}:
        return _malformed_result("The UPI link has an unsupported or missing action.")

    try:
        fields = _parse_query(parsed.query)
    except ValueError:
        return _malformed_result("The UPI link contains too many query fields.")
    features = _features(fields, action, parse_valid=True)
    indicators: list[Indicator] = []

    if action in {"collect", "mandate"}:
        indicators.append(
            Indicator(
                code="UPI_COLLECT_REQUEST",
                severity="medium",
                message=(
                    "This link uses a collect-style request, which asks the recipient "
                    "to pay; scammers may disguise one as a refund. You never need a "
                    "PIN to receive money."
                ),
                evidence={"action": action},
            )
        )

    payee_vpa = fields.get("pa")
    if payee_vpa is not None:
        if _VPA_PATTERN.fullmatch(payee_vpa) is None:
            indicators.append(
                Indicator(
                    code="INVALID_VPA_FORMAT",
                    severity="medium",
                    message="The payee address does not match the expected UPI address format.",
                    evidence={"payee_vpa": payee_vpa},
                )
            )
        else:
            handle = payee_vpa.rsplit("@", maxsplit=1)[1].lower()
            if handle not in {item.lower() for item in _load_config().known_handles}:
                indicators.append(
                    Indicator(
                        code="UNKNOWN_PSP_HANDLE",
                        severity="low",
                        message="The UPI address uses a handle not found in the configured list.",
                        evidence={"handle": handle},
                    )
                )

    amount = fields.get("am")
    if amount is not None:
        indicators.append(_amount_indicator(amount))

    payee_name = fields.get("pn")
    if payee_name and payee_vpa and _brand_name_mismatch(payee_name, payee_vpa):
        indicators.append(
            Indicator(
                code="PAYEE_NAME_BRAND_MISMATCH",
                severity="medium",
                message=(
                    "The displayed payee name uses a brand or authority term that "
                    "does not appear in the UPI address."
                ),
                evidence={"payee_name": payee_name, "payee_vpa": payee_vpa},
            )
        )

    if not fields.get("tr"):
        indicators.append(
            Indicator(
                code="MISSING_TRANSACTION_REF",
                severity="info",
                message="The link does not include a transaction reference.",
                evidence={"transaction_ref_present": False},
            )
        )

    currency = fields.get("cu")
    if currency and currency.upper() != "INR":
        indicators.append(
            Indicator(
                code="NON_INR_CURRENCY",
                severity="low",
                message="The link specifies a currency other than Indian rupees.",
                evidence={"currency": currency},
            )
        )

    note = fields.get("tn")
    if note and _SUSPICIOUS_NOTE_WORDS.search(note):
        indicators.append(
            Indicator(
                code="SUSPICIOUS_NOTE_TEXT",
                severity="medium",
                message="The payment note contains urgency, refund, or account-verification wording.",
                evidence={"note": note},
            )
        )

    return UpiResult(indicators=indicators, features=features)


def _analyze_web_url(parsed: SplitResult) -> UpiResult:
    try:
        fields = _parse_query(parsed.query)
    except ValueError:
        return _malformed_result("The web URL contains too many query fields.")
    features = _features(fields, "web_url", parse_valid=True)
    has_upi_fields = "pa" in fields or "pn" in fields
    indicators = []
    if parsed.scheme.lower() == "https" and has_upi_fields:
        indicators.append(
            Indicator(
                code="UPI_EMBEDDED_IN_WEB_URL",
                severity="low",
                message="This HTTPS web address carries UPI payment fields in its query.",
                evidence={
                    "host": parsed.hostname,
                    "upi_fields": ",".join(
                        key for key in ("pa", "pn") if key in fields
                    ),
                },
            )
        )
    return UpiResult(indicators=indicators, features=features)


def _amount_indicator(amount: str) -> Indicator:
    config = _load_config()
    severity = "low"
    try:
        parsed_amount = Decimal(amount)
        if not parsed_amount.is_finite() or parsed_amount < 0:
            raise InvalidOperation
        if parsed_amount >= config.amount_thresholds.high:
            severity = "high"
        elif parsed_amount >= config.amount_thresholds.medium:
            severity = "medium"
    except InvalidOperation:
        parsed_amount = None
    amount_value = float(parsed_amount) if parsed_amount is not None else None
    if amount_value is not None and not math.isfinite(amount_value):
        amount_value = None
    return Indicator(
        code="PREFILLED_AMOUNT",
        severity=severity,
        message="The link contains a prefilled payment amount.",
        evidence={
            "amount": amount,
            "amount_value": amount_value,
        },
    )


def _brand_name_mismatch(payee_name: str, payee_vpa: str) -> bool:
    config = _load_config()
    name = payee_name.casefold()
    terms = [*config.brand_keywords, *config.authority_words]
    matched_terms = [term.casefold() for term in terms if term.casefold() in name]
    if not matched_terms:
        return False
    address = payee_vpa.casefold()
    return not any(term in address for term in matched_terms)


def _features(
    fields: dict[str, str], action: str, *, parse_valid: bool
) -> dict[str, str | bool | float | None]:
    key_map = {
        "payee_vpa": "pa",
        "payee_name": "pn",
        "amount": "am",
        "transaction_ref": "tr",
        "note": "tn",
        "currency": "cu",
        "mode": "mode",
        "merchant_code": "mc",
    }
    return {
        "action": action,
        **{feature: fields.get(query_key) for feature, query_key in key_map.items()},
        "parse_valid": parse_valid,
    }


def _parse_query(query: str) -> dict[str, str]:
    return dict(parse_qsl(query, keep_blank_values=True, max_num_fields=100))


def _upi_action(parsed) -> str:
    authority = parsed.netloc.lower()
    if authority in {"pay", "collect", "mandate"}:
        return authority
    return parsed.path.strip("/").split("/", maxsplit=1)[0].lower()


def _safe_urlsplit(value: str) -> SplitResult | None:
    try:
        return urlsplit(value)
    except ValueError:
        return None


def _malformed_result(message: str) -> UpiResult:
    indicator = Indicator(
        code="MALFORMED_UPI_URI",
        severity="low",
        message=message,
        evidence={"parse_valid": False},
    )
    return UpiResult(
        indicators=[indicator],
        features={
            "action": "unknown",
            **{feature: None for feature in _FEATURE_NAMES},
            "parse_valid": False,
        },
    )
