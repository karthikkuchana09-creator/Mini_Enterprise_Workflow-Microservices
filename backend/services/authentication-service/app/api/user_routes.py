from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.constants import UserRole
from app.db.session import get_db
from app.dependencies.auth_deps import get_current_user, require_role
from app.schemas.user import (
    UserBase,
    UserProfileSetupRequest,
    UserProfileUpdate,
    UserStatusUpdate,
)
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserBase)
def get_me(user=Depends(get_current_user)):
    return user


@router.patch("/me", response_model=UserBase)
def update_me(
    payload: UserProfileUpdate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = UserService(db)
    service.update_profile(user.id, **payload.model_dump(exclude_none=True))
    if payload.full_name:
        user.full_name = payload.full_name
    return user


@router.post("/me/profile", response_model=UserBase)
def setup_profile(
    payload: UserProfileSetupRequest,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = UserService(db)
    service.update_profile(
        user.id,
        full_name=payload.full_name,
        phone=payload.phone,
        avatar_url=payload.avatar_url,
        bio=payload.bio,
    )
    user.full_name = payload.full_name
    return user


@router.get("/{user_id}", response_model=UserBase)
def get_user(
    user_id: str,
    user=Depends(require_role(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
):
    return UserService(db).get_by_id(user_id)


@router.patch("/me/status", response_model=UserBase)
def update_my_status(
    payload: UserStatusUpdate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return UserService(db).update_status(user.id, payload.status)
