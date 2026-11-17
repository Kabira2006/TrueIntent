"""Update brand_references table for Phase 7 visual matching.

Revision ID: 0003
Revises: 0002
Create Date: 2024-11-16
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade brand_references table with full hash fields."""
    # Drop the old table and recreate (simpler than column-by-column migration)
    op.drop_table('brand_references')
    
    op.create_table(
        'brand_references',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('brand_id', sa.String(length=100), nullable=False),
        sa.Column('brand_name', sa.String(length=255), nullable=False),
        sa.Column('official_domains', postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column('source_url', sa.Text(), nullable=False),
        sa.Column('final_url', sa.Text(), nullable=True),
        sa.Column('reference_type', sa.String(length=50), server_default=sa.text("'login'"), nullable=False),
        sa.Column('capture_quality', sa.String(length=20), nullable=False),
        sa.Column('phash_hex', sa.String(length=64), nullable=True),
        sa.Column('dhash_hex', sa.String(length=64), nullable=True),
        sa.Column('upper_phash_hex', sa.String(length=64), nullable=True),
        sa.Column('favicon_sha256', sa.String(length=64), nullable=True),
        sa.Column('favicon_phash_hex', sa.String(length=64), nullable=True),
        sa.Column('captured_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create index on brand_id for faster lookups
    op.create_index('ix_brand_references_brand_id', 'brand_references', ['brand_id'])


def downgrade() -> None:
    """Downgrade to old brand_references schema."""
    op.drop_index('ix_brand_references_brand_id', table_name='brand_references')
    op.drop_table('brand_references')
    
    # Recreate old table
    op.create_table(
        'brand_references',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('brand_name', sa.String(length=255), nullable=False),
        sa.Column('official_domain', sa.String(length=255), nullable=False),
        sa.Column('phash_signature', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
