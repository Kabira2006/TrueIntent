"""Combine check results into stable advisory pillars and model features."""

import math
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from app.core.models import Indicator

PillarStatus = Literal[
    "NOT_APPLICABLE", "NO_INDICATORS", "FLAGGED", "UNAVAILABLE", "PENDING"
]
OverallIndicator = Literal[
    "NO_INDICATORS_DETECTED",
    "SOME_INDICATORS_DETECTED",
    "HIGH_RISK_INDICATORS_DETECTED",
    "INCONCLUSIVE",
]

_SEVERITY_WEIGHTS = {"info": 0.01, "low": 0.05, "medium": 0.15, "high": 0.3}
_UNAVAILABLE_INDICATOR_CODES = {
    "CHECK_UNAVAILABLE",
    "DNS_LOOKUP_UNAVAILABLE",
    "INFRASTRUCTURE_UNAVAILABLE",
    "THREAT_FEED_UNAVAILABLE",
    "WHOIS_TIMEOUT_OR_UNAVAILABLE",
}


class AdvisoryPillar(BaseModel):
    """One named analysis area and its stable indicator list."""

    model_config = ConfigDict(extra="forbid")

    status: PillarStatus
    indicators: list[Indicator]


class AdvisoryReport(BaseModel):
    """Three advisory pillars and a non-verdict overall indicator."""

    model_config = ConfigDict(extra="forbid")

    technical_url_analysis: AdvisoryPillar
    visual_brand_analysis: AdvisoryPillar
    transaction_context_analysis: AdvisoryPillar
    overall_indicator: OverallIndicator
    signal_vector: dict[str, float | int | bool]
    # This uncalibrated weighted heuristic is for downstream model work only;
    # it is not a probability and must not be presented as one to users.
    heuristic_score: float


def build_report(
    lexical: Any,
    infra: Any,
    feeds: Any,
    upi: Any,
    sandbox: Any | None,
    *,
    payload_type: str = "URL",
    web_payload: bool | None = None,
) -> AdvisoryReport:
    """Build pillars, a flat signal vector, and an uncalibrated score."""
    lexical_indicators = _indicators(lexical)
    infra_indicators = _indicators(infra)
    feed_indicators = _indicators(feeds)
    upi_indicators = _indicators(upi)
    sandbox_indicators = _indicators(sandbox)

    has_web_payload = payload_type == "URL" if web_payload is None else web_payload
    technical = (
        _pillar(
            [*lexical_indicators, *infra_indicators, *feed_indicators],
            checks=(lexical, infra, feeds),
        )
        if has_web_payload
        else AdvisoryPillar(status="NOT_APPLICABLE", indicators=[])
    )
    if has_web_payload and payload_type == "URL":
        visual = (
            _pillar(sandbox_indicators, checks=(sandbox,))
            if sandbox is not None
            else AdvisoryPillar(status="PENDING", indicators=[])
        )
    else:
        visual = AdvisoryPillar(status="NOT_APPLICABLE", indicators=[])

    if payload_type == "UPI_DEEP_LINK" or (
        payload_type == "QR_TEXT" and upi is not None
    ):
        transaction = _pillar(upi_indicators, checks=(upi,))
    else:
        transaction = AdvisoryPillar(status="NOT_APPLICABLE", indicators=[])

    all_indicators = [
        *technical.indicators,
        *visual.indicators,
        *transaction.indicators,
    ]
    any_unavailable = any(
        pillar.status in {"UNAVAILABLE", "PENDING"}
        for pillar in (technical, visual, transaction)
    )
    if any(indicator.severity == "high" for indicator in all_indicators):
        overall: OverallIndicator = "HIGH_RISK_INDICATORS_DETECTED"
    elif any_unavailable:
        overall = "INCONCLUSIVE"
    elif all_indicators:
        overall = "SOME_INDICATORS_DETECTED"
    else:
        overall = "NO_INDICATORS_DETECTED"

    signal_vector = _signal_vector(
        lexical, infra, feeds, upi, all_indicators, payload_type
    )
    return AdvisoryReport(
        technical_url_analysis=technical,
        visual_brand_analysis=visual,
        transaction_context_analysis=transaction,
        overall_indicator=overall,
        signal_vector=signal_vector,
        heuristic_score=_heuristic_score(all_indicators),
    )


def _pillar(indicators: list[Indicator], *, checks: Sequence[Any]) -> AdvisoryPillar:
    if any(_check_status(check) == "UNAVAILABLE" for check in checks):
        return AdvisoryPillar(status="UNAVAILABLE", indicators=indicators)
    substantive_indicators = [
        item for item in indicators if item.code not in _UNAVAILABLE_INDICATOR_CODES
    ]
    if substantive_indicators:
        return AdvisoryPillar(status="FLAGGED", indicators=indicators)
    if indicators or any(_check_status(check) == "UNAVAILABLE" for check in checks):
        return AdvisoryPillar(status="UNAVAILABLE", indicators=indicators)
    if any(_check_status(check) == "PENDING" for check in checks):
        return AdvisoryPillar(status="PENDING", indicators=[])
    if checks and all(_check_status(check) == "UNAVAILABLE" for check in checks):
        return AdvisoryPillar(status="UNAVAILABLE", indicators=[])
    return AdvisoryPillar(status="NO_INDICATORS", indicators=[])


def _indicators(result: Any) -> list[Indicator]:
    raw_indicators = _value(result, "indicators", [])
    if not isinstance(raw_indicators, Sequence) or isinstance(
        raw_indicators, (str, bytes)
    ):
        return []
    indicators: list[Indicator] = []
    for item in raw_indicators:
        try:
            indicators.append(
                item if isinstance(item, Indicator) else Indicator.model_validate(item)
            )
        except (TypeError, ValueError):
            continue
    return indicators


def _check_status(result: Any) -> str | None:
    status = _value(result, "status")
    return status if isinstance(status, str) else None


def _value(result: Any, name: str, default: Any = None) -> Any:
    if isinstance(result, Mapping):
        return result.get(name, default)
    return getattr(result, name, default)


def _signal_vector(
    lexical: Any,
    infra: Any,
    feeds: Any,
    upi: Any,
    indicators: list[Indicator],
    payload_type: str,
) -> dict[str, float | int | bool]:
    lexical_features = _features(lexical)
    infra_features = _features(infra)
    feed_features = _features(feeds)
    upi_features = _features(upi)
    values: dict[str, float | int | bool] = {
        "shannon_entropy": _number(
            lexical_features.get(
                "shannon_entropy", lexical_features.get("entropy", 0.0)
            )
        ),
        "domain_age_days": _number(infra_features.get("domain_age_days"), fallback=-1),
        "subdomain_depth": int(_number(lexical_features.get("subdomain_depth", 0))),
        "is_punycode": _flag(lexical_features.get("is_punycode", False)),
        "gsb_match_count": int(_number(feed_features.get("gsb_match_count", 0))),
        "vt_malicious_count": int(_number(feed_features.get("vt_malicious_count", 0))),
        "upi_collect_request": int(
            any(item.code == "UPI_COLLECT_REQUEST" for item in indicators)
        ),
        "upi_prefilled_amount": int(
            any(item.code == "PREFILLED_AMOUNT" for item in indicators)
        ),
        "payload_is_url": int(payload_type == "URL"),
        "payload_is_upi": int(payload_type == "UPI_DEEP_LINK"),
        "payload_is_qr_text": int(payload_type == "QR_TEXT"),
    }
    for indicator in indicators:
        values[f"indicator_{indicator.code.lower()}"] = 1
    for key in ("domain_age_days", "shannon_entropy", "subdomain_depth"):
        if key in infra_features:
            values[f"infrastructure_{key}"] = _number(infra_features[key])
    if "domain_age_days" in upi_features:
        values["upi_domain_age_days"] = _number(upi_features["domain_age_days"])
    return values


def _features(result: Any) -> Mapping[str, Any]:
    features = _value(result, "features", {})
    return features if isinstance(features, Mapping) else {}


def _number(value: Any, *, fallback: float = 0.0) -> float:
    if isinstance(value, bool):
        return float(value)
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    return number if math.isfinite(number) else fallback


def _flag(value: Any) -> bool:
    return value is True or value == 1


def _heuristic_score(indicators: list[Indicator]) -> float:
    """Sum fixed severity weights and cap at one; this is not calibrated."""
    return min(
        1.0,
        sum(
            _SEVERITY_WEIGHTS[item.severity]
            for item in indicators
            if item.code not in _UNAVAILABLE_INDICATOR_CODES
        ),
    )
