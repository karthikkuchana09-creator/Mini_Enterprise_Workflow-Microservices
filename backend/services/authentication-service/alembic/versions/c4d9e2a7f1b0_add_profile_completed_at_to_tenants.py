"""add profile_completed_at to tenants

Revision ID: c4d9e2a7f1b0
Revises: fb1f8090a5ab
Create Date: 2026-09-01 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4d9e2a7f1b0'
down_revision: Union[str, Sequence[str], None] = 'fb1f8090a5ab'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Timestamp recorded when the organization profile setup is completed.
    op.add_column(
        'tenants',
        sa.Column('profile_completed_at', sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('tenants', 'profile_completed_at')