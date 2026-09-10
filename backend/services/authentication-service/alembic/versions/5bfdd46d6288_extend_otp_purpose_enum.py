"""extend_otp_purpose_enum

Revision ID: 5bfdd46d6288
Revises: 3832b17a0112
Create Date: 2026-09-01 14:05:55.581024

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5bfdd46d6288'
down_revision: Union[str, Sequence[str], None] = '3832b17a0112'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Extend otp_purpose enum with canonical purposes (registration, forgot_password).
    # SQLite stores enums as VARCHAR and ignores native enum ALTER, so guard with
    # dialect detection to keep the migration portable across SQLite/MySQL.
    bind = op.get_bind()
    dialect = bind.dialect.name if bind is not None else "sqlite"

    if dialect != "sqlite":
        new_enum = sa.Enum(
            "registration",
            "forgot_password",
            "email_verify",
            "password_reset",
            name="otp_purpose",
        )
        with op.batch_alter_table("auth_otp", schema=None) as batch_op:
            batch_op.alter_column(
                "purpose",
                existing_type=sa.Enum(
                    "email_verify",
                    "password_reset",
                    name="otp_purpose",
                ),
                type_=new_enum,
                existing_nullable=False,
            )


def downgrade() -> None:
    """Downgrade schema."""
    bind = op.get_bind()
    dialect = bind.dialect.name if bind is not None else "sqlite"

    if dialect != "sqlite":
        old_enum = sa.Enum(
            "email_verify",
            "password_reset",
            name="otp_purpose",
        )
        with op.batch_alter_table("auth_otp", schema=None) as batch_op:
            batch_op.alter_column(
                "purpose",
                existing_type=sa.Enum(
                    "registration",
                    "forgot_password",
                    "email_verify",
                    "password_reset",
                    name="otp_purpose",
                ),
                type_=old_enum,
                existing_nullable=False,
            )
