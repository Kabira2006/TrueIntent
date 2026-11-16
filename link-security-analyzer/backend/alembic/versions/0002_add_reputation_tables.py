"""add reputation tables

Revision ID: 0002
Revises: 0001_initial
Create Date: 2026-11-16

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0002'
down_revision: Union[str, None] = '0001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create feed_meta table
    op.create_table(
        'feed_meta',
        sa.Column('source', sa.String(64), primary_key=True, nullable=False),
        sa.Column('fetched_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('row_count', sa.Integer, nullable=False, server_default='0'),
        sa.Column('license_note', sa.Text, nullable=True),
        sa.Column('detail', postgresql.JSONB, nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    
    # Create tranco_rank table
    op.create_table(
        'tranco_rank',
        sa.Column('registrable_domain', sa.String(255), primary_key=True, nullable=False),
        sa.Column('rank', sa.Integer, nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('idx_tranco_rank_rank', 'tranco_rank', ['rank'])
    
    # Create blocklist_entries table
    op.create_table(
        'blocklist_entries',
        sa.Column('id', sa.UUID, primary_key=True, server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('url_norm', sa.Text, nullable=False),
        sa.Column('registrable_domain', sa.String(255), nullable=False),
        sa.Column('source', sa.String(64), nullable=False),
        sa.Column('threat_type', sa.String(64), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('fetched_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('idx_blocklist_url_norm', 'blocklist_entries', ['url_norm'], postgresql_using='hash')
    op.create_index('idx_blocklist_domain', 'blocklist_entries', ['registrable_domain'])
    op.create_index('idx_blocklist_source', 'blocklist_entries', ['source'])


def downgrade() -> None:
    op.drop_index('idx_blocklist_source', table_name='blocklist_entries')
    op.drop_index('idx_blocklist_domain', table_name='blocklist_entries')
    op.drop_index('idx_blocklist_url_norm', table_name='blocklist_entries')
    op.drop_table('blocklist_entries')
    
    op.drop_index('idx_tranco_rank_rank', table_name='tranco_rank')
    op.drop_table('tranco_rank')
    
    op.drop_table('feed_meta')
