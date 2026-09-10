"""add email_verified to auth_credentials

Revision ID: fb1f8090a5ab
Revises: 5bfdd46d6288
Create Date: 2026-09-01 14:30:41.854539

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fb1f8090a5ab'
down_revision: Union[str, Sequence[str], None] = '5bfdd46d6288'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add email_verified to auth_credentials (default False for existing rows).
    op.add_column(
        'auth_credentials',
        sa.Column(
            'email_verified',
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('auth_credentials', 'email_verified')
