from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.core.constants import UserRole, UserStatus, UserType


class UserBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    full_name: str
    user_type: UserType
    role: UserRole
    status: UserStatus
    tenant_id: Optional[str] = None


class UserProfileUpdate(BaseModel):
    full_name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    phone: Optional[str] = Field(default=None, max_length=50)
    avatar_url: Optional[str] = Field(default=None, max_length=500)
    bio: Optional[str] = Field(default=None, max_length=2000)
    preferences: Optional[dict] = None


class UserProfileSetupRequest(BaseModel):
    full_name: str = Field(min_length=1, max_length=255)
    phone: Optional[str] = Field(default=None, max_length=50)
    avatar_url: Optional[str] = Field(default=None, max_length=500)
    bio: Optional[str] = Field(default=None, max_length=2000)


class UserStatusUpdate(BaseModel):
    status: UserStatus


class UserListResponse(BaseModel):
    users: list[UserBase]
    total: int
