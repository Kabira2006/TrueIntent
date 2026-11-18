"""allow sandbox lifecycle statuses

Revision ID: 0004_expand_scan_statuses
Revises: 0003
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0004_expand_scan_statuses"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("ck_scan_jobs_status", "scan_jobs", type_="check")
    op.create_check_constraint(
        "ck_scan_jobs_status",
        "scan_jobs",
        "status IN ('PENDING','FAST_PATH_DONE','sandbox_queued','sandbox_running','COMPLETED','complete_partial','FAILED')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_scan_jobs_status", "scan_jobs", type_="check")
    op.create_check_constraint(
        "ck_scan_jobs_status",
        "scan_jobs",
        "status IN ('PENDING','FAST_PATH_DONE','COMPLETED','FAILED')",
    )
