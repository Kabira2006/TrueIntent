"""Shared typed result models for pure input analysis."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class Indicator(BaseModel):
    """One explainable fact detected in an input."""

    model_config = ConfigDict(extra="forbid")

    code: str
    severity: Literal["info", "low", "medium", "high"]
    message: str
    evidence: dict[str, str | int | float | bool | None]


class InputClassification(BaseModel):
    """The kind of input received and any link found inside it."""

    model_config = ConfigDict(extra="forbid")

    payload_type: Literal["URL", "UPI_DEEP_LINK", "QR_TEXT"]
    normalized_payload: str
    embedded_payload: str | None = None
    recognized: bool


class UpiResult(BaseModel):
    """Facts extracted from a UPI link or a web URL carrying UPI fields."""

    model_config = ConfigDict(extra="forbid")

    indicators: list[Indicator]
    features: dict[str, str | bool | float | None]
