from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.constants import UserRole, UserStatus, UserType
from app.models.user import User, UserProfile


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_user(
        self,
        email: str,
        full_name: str,
        user_type: UserType,
        role: UserRole,
        status: UserStatus = UserStatus.PENDING,
        tenant_id: Optional[str] = None,
    ) -> User:
        user = User(
            email=email,
            full_name=full_name,
            user_type=user_type,
            role=role,
            status=status,
            tenant_id=tenant_id,
        )
        self.db.add(user)
        self.db.flush()
        return user

    def create_profile(self, user_id: str) -> UserProfile:
        profile = UserProfile(user_id=user_id)
        self.db.add(profile)
        self.db.flush()
        return profile

    def get_by_id(self, user_id: str) -> Optional[User]:
        return self.db.get(User, user_id)

    def get_by_email(self, email: str) -> Optional[User]:
        return self.db.scalar(select(User).where(User.email == email))

    def get_profile(self, user_id: str) -> Optional[UserProfile]:
        return self.db.scalar(
            select(UserProfile).where(UserProfile.user_id == user_id)
        )

    def update_user(
        self,
        user: User,
        full_name: Optional[str] = None,
        role: Optional[UserRole] = None,
        status: Optional[UserStatus] = None,
        tenant_id: Optional[str] = None,
    ) -> User:
        if full_name is not None:
            user.full_name = full_name
        if role is not None:
            user.role = role
        if status is not None:
            user.status = status
        if tenant_id is not None:
            user.tenant_id = tenant_id
        self.db.flush()
        return user

    def update_profile(
        self,
        profile: UserProfile,
        phone: Optional[str] = None,
        avatar_url: Optional[str] = None,
        bio: Optional[str] = None,
        preferences: Optional[dict] = None,
    ) -> UserProfile:
        if phone is not None:
            profile.phone = phone
        if avatar_url is not None:
            profile.avatar_url = avatar_url
        if bio is not None:
            profile.bio = bio
        if preferences is not None:
            profile.preferences = preferences
        self.db.flush()
        return profile

    def list_by_tenant(self, tenant_id: str) -> list[User]:
        return self.db.scalars(
            select(User).where(User.tenant_id == tenant_id).order_by(User.created_at)
        ).all()

    def count_by_tenant(self, tenant_id: str) -> int:
        return self.db.scalar(
            select(func.count()).select_from(User).where(User.tenant_id == tenant_id)
        ) or 0

    def count_active_by_tenant(self, tenant_id: str) -> int:
        return self.db.scalar(
            select(func.count()).select_from(User).where(
                User.tenant_id == tenant_id,
                User.status == UserStatus.ACTIVE,
            )
        ) or 0
