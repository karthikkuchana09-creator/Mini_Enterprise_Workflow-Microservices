import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Enum, String, func
from sqlalchemy.orm import Mapped, mapped_column

from tenant.constants import TenantStatus, UserRole
from tenant.database import Base


def _uuid_str() -> str:
    return str(uuid.uuid4())


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tenant_code: Mapped[Optional[str]] = mapped_column(
        String(32), unique=True, index=True, nullable=True
    )
    org_email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    status: Mapped[TenantStatus] = mapped_column(
        Enum(TenantStatus, name="tenant_status", values_callable=lambda e: [m.value for m in e]),
        default=TenantStatus.PENDING,
        nullable=False,
    )
    is_complete: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    profile_completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    settings: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class TenantAdmin(Base):
    __tablename__ = "tenant_admins"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class TenantInvitation(Base):
    __tablename__ = "tenant_invitations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="invite_role", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    accepted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())