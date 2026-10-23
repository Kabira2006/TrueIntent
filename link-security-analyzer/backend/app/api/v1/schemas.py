"""Validated request and response contracts for the scan API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.core.aggregator import AdvisoryPillar, OverallIndicator


class ScanRequest(BaseModel):
    """One user-provided URL, UPI link, or QR text."""

    model_config = ConfigDict(extra="forbid")

    input: str = Field(min_length=1, max_length=2048)


class FastPathSummary(BaseModel):
    """Small summary returned immediately after a scan is submitted."""

    model_config = ConfigDict(extra="forbid")

    payload_type: Literal["URL", "UPI_DEEP_LINK", "QR_TEXT"]
    domain: str | None
    is_punycode: bool
    shannon_entropy: float
    domain_age_days: int | None
    threat_feed_matches: int


class ScanAccepted(BaseModel):
    """Accepted scan identifier and polling location."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    status: Literal["FAST_PATH_DONE", "COMPLETED"]
    fast_path_summary: FastPathSummary
    poll_url: str


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
    status: Literal["FAST_PATH_DONE", "COMPLETED", "FAILED"]
    overall_indicator: OverallIndicator
    advisory_report: AdvisoryReportResponse
    # This score is an uncalibrated internal feature, not a probability and is
    # intentionally not returned in this user-facing response.
