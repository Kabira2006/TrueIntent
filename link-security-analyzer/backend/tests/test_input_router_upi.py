"""Pure input-router and UPI parser tests; no network, Redis, or Postgres."""

import pytest

from app.core.input_router import classify_input
from app.core.upi import analyze_upi


@pytest.mark.parametrize(
    ("raw", "payload_type", "normalized", "recognized"),
    [
        (" https://Example.com/path ", "URL", "https://example.com/path", True),
        ("HTTP://example.com", "URL", "http://example.com", True),
        ("http://127.0.0.1:8000/health", "URL", "http://127.0.0.1:8000/health", True),
        ("example.com", "URL", "example.com", True),
        ("shop.example.co.in/path", "URL", "shop.example.co.in/path", True),
        (
            "upi://pay?pa=demo%40okhdfcbank",
            "UPI_DEEP_LINK",
            "upi://pay?pa=demo%40okhdfcbank",
            True,
        ),
        (
            "UPI://collect?pa=demo%40oksbi",
            "UPI_DEEP_LINK",
            "upi://collect?pa=demo%40oksbi",
            True,
        ),
        (
            "Scan here: https://example.com/pay now",
            "QR_TEXT",
            "https://example.com/pay",
            True,
        ),
        (
            "Scan: upi://pay?pa=demo%40okhdfcbank.",
            "QR_TEXT",
            "upi://pay?pa=demo%40okhdfcbank",
            True,
        ),
        ("A receipt with no link", "QR_TEXT", None, False),
        ("https://example.com/refund", "URL", "https://example.com/refund", True),
    ],
)
def test_classify_input(
    raw: str, payload_type: str, normalized: str, recognized: bool
) -> None:
    result = classify_input(raw)
    assert result.payload_type == payload_type
    assert result.recognized is recognized
    if payload_type == "QR_TEXT":
        assert result.embedded_payload == normalized
    else:
        assert result.normalized_payload == normalized


@pytest.mark.parametrize("raw", ["", " \t\n", "\u200b\u200c"])
def test_classify_rejects_empty_after_normalization(raw: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        classify_input(raw)


def test_classify_rejects_input_over_2048_characters() -> None:
    with pytest.raises(ValueError, match="2048"):
        classify_input("x" * 2049)


def test_classify_trims_before_checking_input_length() -> None:
    result = classify_input(f"{' ' * 1024}example.com{' ' * 1024}")
    assert result.payload_type == "URL"
    assert result.normalized_payload == "example.com"


def test_classify_strips_control_and_zero_width_characters() -> None:
    result = classify_input("https://exa\u200bmple.com/\x00path")
    assert result.normalized_payload == "https://example.com/path"


def test_classify_rejects_non_string_input() -> None:
    with pytest.raises(TypeError, match="string"):
        classify_input(None)  # type: ignore[arg-type]


def test_upi_extracts_and_decodes_all_payment_fields() -> None:
    result = analyze_upi(
        "upi://pay?pa=demo%40okhdfcbank&pn=Jos%C3%A9%20%E2%9C%93&am=12.50"
        "&tr=ref-1&tn=Lunch%20today&cu=INR&mode=02&mc=5812"
    )
    assert result.features == {
        "action": "pay",
        "payee_vpa": "demo@okhdfcbank",
        "payee_name": "José ✓",
        "amount": "12.50",
        "transaction_ref": "ref-1",
        "note": "Lunch today",
        "currency": "INR",
        "mode": "02",
        "merchant_code": "5812",
        "parse_valid": True,
    }
    assert {indicator.code for indicator in result.indicators} == {"PREFILLED_AMOUNT"}


@pytest.mark.parametrize(
    ("payload", "expected_code"),
    [
        ("upi://collect?pa=demo%40oksbi&tr=x", "UPI_COLLECT_REQUEST"),
        ("upi://mandate?pa=demo%40oksbi&tr=x", "UPI_COLLECT_REQUEST"),
        ("upi://pay?pa=x%40oksbi", "INVALID_VPA_FORMAT"),
        ("upi://pay?pa=demo%40unknownpsp&tr=x", "UNKNOWN_PSP_HANDLE"),
        ("upi://pay?pa=demo%40oksbi&am=10", "PREFILLED_AMOUNT"),
        ("upi://pay?pa=demo%40oksbi&am=1000", "PREFILLED_AMOUNT"),
        ("upi://pay?pa=demo%40oksbi&am=10000", "PREFILLED_AMOUNT"),
        (
            "upi://pay?pa=person%40ybl&pn=Refund%20Support&tr=x",
            "PAYEE_NAME_BRAND_MISMATCH",
        ),
        ("upi://pay?pa=demo%40oksbi", "MISSING_TRANSACTION_REF"),
        ("upi://pay?pa=demo%40oksbi&tr=x&cu=USD", "NON_INR_CURRENCY"),
        ("upi://pay?pa=demo%40oksbi&tr=x&tn=Urgent%20refund", "SUSPICIOUS_NOTE_TEXT"),
    ],
)
def test_upi_indicators(payload: str, expected_code: str) -> None:
    result = analyze_upi(payload)
    assert expected_code in {indicator.code for indicator in result.indicators}


def test_collect_message_gives_pin_guidance() -> None:
    result = analyze_upi("upi://collect?pa=demo%40oksbi")
    indicator = next(
        item for item in result.indicators if item.code == "UPI_COLLECT_REQUEST"
    )
    assert "never need a PIN to receive money" in indicator.message
    assert "asks the recipient to pay" in indicator.message


def test_amount_severity_uses_configured_thresholds() -> None:
    results = [
        analyze_upi(f"upi://pay?pa=demo%40oksbi&am={amount}")
        for amount in ("999.99", "1000", "10000")
    ]
    severities = [
        next(
            item for item in result.indicators if item.code == "PREFILLED_AMOUNT"
        ).severity
        for result in results
    ]
    assert severities == ["low", "medium", "high"]


@pytest.mark.parametrize(
    "payload",
    [
        "not a uri",
        "upi://",
        "upi://unknown?pa=demo%40oksbi",
        "upi://[bad",
    ],
)
def test_malformed_uri_returns_explicit_indicator(payload: str) -> None:
    result = analyze_upi(payload)
    assert result.features["parse_valid"] is False
    assert result.indicators[0].code == "MALFORMED_UPI_URI"


def test_https_url_with_upi_query_is_reported() -> None:
    result = analyze_upi("https://example.com/pay?pa=demo%40oksbi&pn=Demo")
    assert result.indicators[0].code == "UPI_EMBEDDED_IN_WEB_URL"
    assert result.features["payee_vpa"] == "demo@oksbi"
