"""Validated request and response contracts for the scan API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import get_settings
from app.core.aggregator import AdvisoryPillar, OverallIndicator


class ScanRequest(BaseModel):
    """One user-provided URL, UPI link, or QR text."""

    model_config = ConfigDict(extra="forbid")

    input: str = Field(min_length=1)
    
    @field_validator("input")
    @classmethod
    def validate_input_length(cls, value: str) -> str:
        """Validate input length against config."""
        max_length = get_settings().max_input_length
        if len(value) > max_length:
            raise ValueError(
                f"Input too long: {len(value)} characters (max {max_length})"
            )
        return value


class FastPathSummary(BaseModel):
    """Small summary returned immediately after a scan is submitted."""

    model_config = ConfigDict(extra="forbid")

    payload_type: Literal["URL", "UPI_DEEP_LINK", "QR_TEXT"]
    domain: str | None
    is_punycode: bool
    shannon_entropy: float
    domain_age_days: int | None
    threat_feed_matches: int


class CheckOut(BaseModel):
    """One executed check with honest status and timing."""

    model_config = ConfigDict(extra="forbid")

    name: str
    status: Literal["ok", "unavailable", "skipped"]
    group: str | None = None
    took_ms: int
    reason: str | None = None


class CoverageOut(BaseModel):
    """Share of check groups that actually ran."""

    model_config = ConfigDict(extra="forbid")

    completed: list[str]
    unavailable: list[dict[str, str]]
    level: Literal["low", "medium", "high"]


class ScanVerdict(BaseModel):
    """Heuristic verdict plus honesty metadata."""

    model_config = ConfigDict(extra="forbid")

    verdict: Literal["DANGEROUS", "SUSPICIOUS", "LIKELY_SAFE", "UNKNOWN"]
    risk_score: int
    risk_score_note: str
    coverage: CoverageOut
    reasons: list[str]


class ScanAccepted(BaseModel):
    """Accepted scan identifier and polling location."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    status: Literal["FAST_PATH_DONE", "COMPLETED", "complete_partial"]
    fast_path_summary: FastPathSummary
    poll_url: str
    verdict: ScanVerdict


class AdvisoryReportResponse(BaseModel):
    """Persisted status and indicators for each of the three pillars."""

    model_config = ConfigDict(extra="forbid")

    technical_url_analysis: AdvisoryPillar
    visual_brand_analysis: AdvisoryPillar
    transaction_context_analysis: AdvisoryPillar


class ScanReport(BaseModel):
    """A report suitable for polling after the fast path completes."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    status: Literal[
        "PENDING",
        "FAST_PATH_DONE",
        "sandbox_queued",
        "sandbox_running",
        "COMPLETED",
        "complete_partial",
        "FAILED",
    ]
    overall_indicator: OverallIndicator
    advisory_report: AdvisoryReportResponse
    # This score is an uncalibrated internal feature, not a probability and is
    # intentionally not returned in this user-facing response.
