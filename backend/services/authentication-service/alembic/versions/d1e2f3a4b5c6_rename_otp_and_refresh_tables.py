"""rename otp / refresh-token tables to spec names

Renames ``auth_otp`` -> ``otp_verifications`` and ``auth_refresh_tokens``
-> ``refresh_tokens`` to match the documented schema, and renames their
indexes accordingly (table rename leaves SQLite index names untouched).

Revision ID: d1e2f3a4b5c6
Revises: c4d9e2a7f1b0
Create Date: 2026-09-08 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd1e2f3a4b5c6'
down_revision: Union[str, Sequence[str], None] = 'c4d9e2a7f1b0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.rename_table('auth_otp', 'otp_verifications')
    op.rename_table('auth_refresh_tokens', 'refresh_tokens')

    op.create_index(op.f('ix_otp_verifications_email'), 'otp_verifications', ['email'], unique=False)
    op.create_index(op.f('ix_refresh_tokens_token_hash'), 'refresh_tokens', ['token_hash'], unique=True)
    op.create_index(op.f('ix_refresh_tokens_user_id'), 'refresh_tokens', ['user_id'], unique=False)

    op.drop_index('ix_auth_otp_email', table_name='otp_verifications')
    op.drop_index('ix_auth_refresh_tokens_token_hash', table_name='refresh_tokens')
    op.drop_index('ix_auth_refresh_tokens_user_id', table_name='refresh_tokens')


def downgrade() -> None:
    """Downgrade schema."""
    op.create_index('ix_auth_refresh_tokens_user_id', 'refresh_tokens', ['user_id'], unique=False)
    op.create_index('ix_auth_refresh_tokens_token_hash', 'refresh_tokens', ['token_hash'], unique=True)
    op.create_index('ix_auth_otp_email', 'otp_verifications', ['email'], unique=False)

    op.drop_index('ix_refresh_tokens_user_id', table_name='refresh_tokens')
    op.drop_index('ix_refresh_tokens_token_hash', table_name='refresh_tokens')
    op.drop_index('ix_otp_verifications_email', table_name='otp_verifications')

    op.rename_table('refresh_tokens', 'auth_refresh_tokens')
    op.rename_table('otp_verifications', 'auth_otp')