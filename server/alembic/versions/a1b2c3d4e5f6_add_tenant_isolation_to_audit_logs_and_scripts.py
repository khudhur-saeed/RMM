"""add_tenant_isolation_to_audit_logs_and_scripts

Revision ID: a1b2c3d4e5f6
Revises: e880dcaa0761
Create Date: 2026-11-08 22:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'e880dcaa0761'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema with tenant isolation columns for audit_logs and scripts."""
    op.add_column('audit_logs', sa.Column('org_id', sa.UUID(), nullable=True))
    op.add_column('audit_logs', sa.Column('site_id', sa.UUID(), nullable=True))
    op.create_index(op.f('ix_audit_logs_org_id'), 'audit_logs', ['org_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_site_id'), 'audit_logs', ['site_id'], unique=False)

    op.add_column('scripts', sa.Column('org_id', sa.UUID(), nullable=True))
    op.add_column(
        'scripts',
        sa.Column('is_system_global', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    )
    op.create_index(op.f('ix_scripts_org_id'), 'scripts', ['org_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_scripts_org_id'), table_name='scripts')
    op.drop_column('scripts', 'is_system_global')
    op.drop_column('scripts', 'org_id')

    op.drop_index(op.f('ix_audit_logs_site_id'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_org_id'), table_name='audit_logs')
    op.drop_column('audit_logs', 'site_id')
    op.drop_column('audit_logs', 'org_id')
