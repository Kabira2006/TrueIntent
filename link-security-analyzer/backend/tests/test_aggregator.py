"""Advisory aggregation tests and user-facing wording guard."""

from typing import Any

import pytest

from app.core.aggregator import build_report
from app.core.models import Indicator
from app.core.threat_feeds import FeedLookup, ThreatFeedResult
from app.core.upi import UpiResult


def _indicator(
    code: str = "SAMPLE_CLUE",
    severity: str = "low",
    message: str = "A sample link clue.",
) -> Indicator:
    return Indicator(
        code=code,
        severity=severity,  # type: ignore[arg-type]
        message=message,
        evidence={"example": True},
    )


def _empty_feed() -> ThreatFeedResult:
    empty = FeedLookup(status="NO_MATCH", indicators=[])
    return ThreatFeedResult(
        google_safe_browsing=empty,
        virustotal=empty,
        indicators=[],
        features={
            "gsb_match_count": 0,
            "vt_malicious_count": 0,
            "vt_total_count": 0,
            "gsb_available": True,
            "vt_available": True,
        },
    )


def test_build_report_creates_three_pillars_and_uncalibrated_score() -> None:
    lexical = {
        "status": "AVAILABLE",
        "indicators": [_indicator()],
        "features": {
            "shannon_entropy": 3.25,
            "subdomain_depth": 2,
            "is_punycode": True,
        },
    }
    infra = {
        "status": "AVAILABLE",
        "indicators": [],
        "features": {"domain_age_days": 12},
    }
    report = build_report(
        lexical,
        infra,
        _empty_feed(),
        None,
        None,
        payload_type="URL",
    )
    assert report.technical_url_analysis.status == "FLAGGED"
    assert report.visual_brand_analysis.status == "PENDING"
    assert report.transaction_context_analysis.status == "NOT_APPLICABLE"
    assert report.overall_indicator == "INCONCLUSIVE"
    assert report.signal_vector["shannon_entropy"] == 3.25
    assert report.signal_vector["domain_age_days"] == 12
    assert report.signal_vector["subdomain_depth"] == 2
    assert report.signal_vector["is_punycode"] is True
    assert report.heuristic_score == pytest.approx(0.05)
    assert 0 <= report.heuristic_score <= 1


def test_high_severity_indicator_sets_high_risk_overall() -> None:
    report = build_report(
        {"indicators": [_indicator(severity="high")]},
        {},
        _empty_feed(),
        None,
        None,
        payload_type="URL",
    )
    assert report.overall_indicator == "HIGH_RISK_INDICATORS_DETECTED"
    assert report.heuristic_score == pytest.approx(0.3)


def test_unavailable_checks_create_inconclusive_report() -> None:
    unavailable = {
        "status": "UNAVAILABLE",
        "indicators": [
            _indicator(
                "CHECK_UNAVAILABLE",
                "info",
                "A check could not be completed.",
            )
        ],
    }
    report = build_report(
        unavailable,
        unavailable,
        unavailable,
        None,
        None,
        payload_type="URL",
    )
    assert report.technical_url_analysis.status == "UNAVAILABLE"
    assert report.overall_indicator == "INCONCLUSIVE"
    assert report.heuristic_score == 0


def test_upi_and_qr_inputs_use_transaction_pillar() -> None:
    upi = UpiResult(
        indicators=[_indicator("UPI_COLLECT_REQUEST", "medium")],
        features={"action": "collect", "parse_valid": True},
    )
    report = build_report(
        {},
        {},
        _empty_feed(),
        upi,
        None,
        payload_type="UPI_DEEP_LINK",
    )
    assert report.transaction_context_analysis.status == "FLAGGED"
    assert report.overall_indicator == "SOME_INDICATORS_DETECTED"
    assert report.signal_vector["upi_collect_request"] == 1


def test_qr_text_with_embedded_web_link_marks_visual_not_applicable() -> None:
    report = build_report(
        {"status": "AVAILABLE", "indicators": []},
        {"status": "AVAILABLE", "indicators": []},
        _empty_feed(),
        None,
        None,
        payload_type="QR_TEXT",
        web_payload=True,
    )
    assert report.technical_url_analysis.status == "NO_INDICATORS"
    assert report.visual_brand_analysis.status == "NOT_APPLICABLE"
    assert report.transaction_context_analysis.status == "NOT_APPLICABLE"


def test_no_findings_reports_no_indicators_and_score_zero() -> None:
    report = build_report(
        {}, {}, _empty_feed(), None, None, payload_type="UPI_DEEP_LINK"
    )
    assert report.overall_indicator == "NO_INDICATORS_DETECTED"
    assert report.heuristic_score == 0


def _message_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        messages = [value["message"]] if isinstance(value.get("message"), str) else []
        return messages + [
            message
            for key, item in value.items()
            if key != "message"
            for message in _message_strings(item)
        ]
    if isinstance(value, list):
        return [message for item in value for message in _message_strings(item)]
    return []


def test_generated_messages_follow_advisory_wording_rules() -> None:
    upi_indicator = Indicator(
        code="UPI_COLLECT_REQUEST",
        severity="medium",
        message=(
            "This link asks the recipient to pay. You never need a PIN to receive money."
        ),
        evidence={"action": "collect"},
    )
    report = build_report(
        {"indicators": [_indicator()]},
        {"indicators": []},
        _empty_feed(),
        UpiResult(
            indicators=[upi_indicator],
            features={"action": "collect", "parse_valid": True},
        ),
        None,
        payload_type="UPI_DEEP_LINK",
    )
    messages = _message_strings(report.model_dump(mode="json"))
    forbidden_phrases = ("safe", "100%", "guaranteed", "confirmed fraud")
    assert all(
        phrase not in message.casefold()
        for message in messages
        for phrase in forbidden_phrases
    )
