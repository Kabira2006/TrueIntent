"""initial schema: domain_records, brand_references, scan_jobs

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-16

gen_random_uuid() is built into PostgreSQL 13+ (pgcrypto not required here
because PG 16 ships it in core). We do not enable the uuid-ossp extension.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "domain_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("domain_name", sa.String(length=255), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("age_days", sa.Integer(), nullable=True),
        sa.Column("registrar", sa.String(length=255), nullable=True),
        sa.Column("has_mx_records", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain_name"),
    )

    op.create_table(
        "brand_references",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("brand_name", sa.String(length=255), nullable=False),
        sa.Column("official_domain", sa.String(length=255), nullable=False),
        sa.Column("phash_signature", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "scan_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("input_payload", sa.Text(), nullable=False),
        sa.Column("payload_type", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), server_default=sa.text("'PENDING'"), nullable=False),
        sa.Column(
            "lexical_indicators", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column(
            "infrastructure_indicators", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column(
            "threat_feed_indicators", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column(
            "transaction_indicators", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column("sandbox_indicators", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column(
            "final_advisory_status", sa.String(length=50), server_default=sa.text("'UNKNOWN'"), nullable=False
        ),
        sa.Column("signal_vector", postgresql.JSONB(), nullable=True),
        sa.Column("heuristic_score", sa.Float(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "payload_type IN ('URL','UPI_DEEP_LINK','QR_TEXT')", name="ck_scan_jobs_payload_type"
        ),
        sa.CheckConstraint(
            "status IN ('PENDING','FAST_PATH_DONE','COMPLETED','FAILED')", name="ck_scan_jobs_status"
        ),
    )
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_scan_jobs_status", table_name="scan_jobs")
    op.drop_table("scan_jobs")
    op.drop_table("brand_references")
    op.drop_table("domain_records")
