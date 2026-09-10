"""Auth Service internal API.

Exposes user-management operations that tenant-service needs (user lookup,
user creation, dashboard counts). The ``users`` table belongs to auth-service,
so every cross-service user call is routed here over HTTP. Protected by the
shared internal API key (``X-Internal-API-Key`` header).

Error statuses follow the ECWF exception mapping handled by
``register_exception_handlers`` (404 / 409 / 422 / 403 / 401...).
"""
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from shared.dependencies.internal_auth import create_internal_auth
from app.core.config import settings
from app.core.constants import UserRole, UserStatus, UserType
from app.db.session import get_db
from app.services.user_service import UserService

router = APIRouter(prefix="/internal", tags=["internal-users"])

verify_internal = create_internal_auth(settings.INTERNAL_API_KEY)


def _user_dict(user) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "user_type": user.user_type.value if hasattr(user.user_type, "value") else user.user_type,
        "role": user.role.value if hasattr(user.role, "value") else user.role,
        "status": user.status.value if hasattr(user.status, "value") else user.status,
        "tenant_id": user.tenant_id,
    }


class InternalUserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)
    user_type: UserType
    role: UserRole
    status: UserStatus = UserStatus.PENDING
    tenant_id: Optional[str] = None


@router.get("/users/dashboard-counts")
def internal_dashboard_counts(
    tenant_id: str,
    api_key: str = Depends(verify_internal),
    db: Session = Depends(get_db),
):
    return UserService(db).dashboard_counts(tenant_id)


@router.get("/users/by-email/{email}")
def internal_get_user_by_email(
    email: str,
    api_key: str = Depends(verify_internal),
    db: Session = Depends(get_db),
):
    user = UserService(db).get_by_email(email)
    if not user:
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return _user_dict(user)


@router.get("/users/{user_id}")
def internal_get_user(
    user_id: str,
    api_key: str = Depends(verify_internal),
    db: Session = Depends(get_db),
):
    # UserService.get_by_id raises NotFoundError (-> 404) for unknown ids.
    user = UserService(db).get_by_id(user_id)
    return _user_dict(user)


@router.post("/users", status_code=201)
def internal_create_user(
    payload: InternalUserCreate,
    api_key: str = Depends(verify_internal),
    db: Session = Depends(get_db),
):
    user = UserService(db).create_user(**payload.model_dump())
    return _user_dict(user)