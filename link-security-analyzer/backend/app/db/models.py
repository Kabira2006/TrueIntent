"""SQLAlchemy 2.x typed table models.

Three tables: a notebook of domains we have seen, a card file of real
brands to compare against, and a job ticket per submitted link.
"""

import uuid
from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Parent class that collects all table definitions."""


class DomainRecord(Base):
    """Cached facts about one domain name, like a notebook page per street."""

    __tablename__ = "domain_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        default=uuid.uuid4,
    )
    domain_name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Cached convenience only. Always derive from registered_at when reading.
    age_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    has_mx_records: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"), default=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    @property
    def derived_age_days(self) -> int | None:
        """Compute age from registered_at; fall back to the cached value."""
        if self.registered_at is not None:
            return (date.today() - self.registered_at.date()).days
        return self.age_days


class BrandReference(Base):
    """One real brand's official domain plus its picture fingerprint."""

    __tablename__ = "brand_references"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        default=uuid.uuid4,
    )
    brand_name: Mapped[str] = mapped_column(String(255), nullable=False)
    official_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    # Perceptual hash signature: a short fingerprint of the logo/page look.
    phash_signature: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ScanJob(Base):
    """One submitted link (or UPI link, or QR text) and its clue collections."""

    __tablename__ = "scan_jobs"
    __table_args__ = (
        CheckConstraint("payload_type IN ('URL','UPI_DEEP_LINK','QR_TEXT')", name="ck_scan_jobs_payload_type"),
        CheckConstraint(
            "status IN ('PENDING','FAST_PATH_DONE','COMPLETED','FAILED')",
            name="ck_scan_jobs_status",
        ),
        Index("ix_scan_jobs_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        default=uuid.uuid4,
    )
    input_payload: Mapped[str] = mapped_column(Text, nullable=False)
    payload_type: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default=text("'PENDING'"), default="PENDING")

    # Each pillar stores its clue list as JSONB (a flexible drawer of labeled cards).
    lexical_indicators: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict)
    infrastructure_indicators: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict
    )
    threat_feed_indicators: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict
    )
    transaction_indicators: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict
    )
    sandbox_indicators: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict
    )

    final_advisory_status: Mapped[str] = mapped_column(
        String(50), nullable=False, server_default=text("'UNKNOWN'"), default="UNKNOWN"
    )

    # Fusion helpers for the later text-scam classifier (nullable until computed).
    signal_vector: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    heuristic_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
