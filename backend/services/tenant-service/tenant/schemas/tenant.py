from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from tenant.constants import TenantStatus, UserRole


class TenantBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    tenant_code: Optional[str] = None
    org_email: str
    status: TenantStatus
    is_complete: bool
    profile_completed_at: Optional[datetime] = None


class TenantProfileUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    org_email: Optional[EmailStr] = None
    settings: Optional[dict] = None


class TenantStatusUpdate(BaseModel):
    status: TenantStatus


class TenantInviteRequest(BaseModel):
    email: EmailStr
    role: UserRole = UserRole.TENANT_USER


class TenantInvitationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    email: str
    role: str
    expires_at: datetime
    accepted_at: Optional[datetime] = None


class InvitationAcceptRequest(BaseModel):
    token: str
    full_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=8, max_length=128)


class DashboardResponse(BaseModel):
    tenant: TenantBase
    total_users: int
    active_users: int
    pending_invitations: int


class TenantCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    tenant_code: Optional[str] = None
    org_email: str
    profile_completed_at: Optional[datetime] = None