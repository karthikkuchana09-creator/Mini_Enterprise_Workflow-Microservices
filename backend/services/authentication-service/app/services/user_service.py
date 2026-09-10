from typing import Optional

from sqlalchemy.orm import Session

from app.core.constants import UserRole, UserStatus, UserType
from app.core.exceptions import EmailAlreadyExistsError, NotFoundError
from app.repositories.user_repo import UserRepository


class UserService:
    def __init__(self, db: Session):
        self.repo = UserRepository(db)

    def create_user(
        self,
        email: str,
        full_name: str,
        user_type: UserType,
        role: UserRole,
        status: UserStatus = UserStatus.PENDING,
        tenant_id: Optional[str] = None,
    ):
        if self.repo.get_by_email(email):
            raise EmailAlreadyExistsError()
        user = self.repo.create_user(
            email=email,
            full_name=full_name,
            user_type=user_type,
            role=role,
            status=status,
            tenant_id=tenant_id,
        )
        self.repo.create_profile(user.id)
        return user

    def get_by_id(self, user_id: str):
        user = self.repo.get_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        return user

    def get_by_email(self, email: str):
        return self.repo.get_by_email(email)

    def activate_user(self, user_id: str):
        user = self.get_by_id(user_id)
        return self.repo.update_user(user, status=UserStatus.ACTIVE)

    def deactivate_user(self, user_id: str):
        user = self.get_by_id(user_id)
        return self.repo.update_user(user, status=UserStatus.INACTIVE)

    def update_status(self, user_id: str, status: UserStatus):
        user = self.get_by_id(user_id)
        return self.repo.update_user(user, status=status)

    def update_role(self, user_id: str, role: UserRole):
        user = self.get_by_id(user_id)
        return self.repo.update_user(user, role=role)

    def update_profile(self, user_id: str, **fields):
        profile = self.repo.get_profile(user_id)
        if not profile:
            raise NotFoundError("Profile not found")
        return self.repo.update_profile(profile, **fields)

    def list_by_tenant(self, tenant_id: str):
        return self.repo.list_by_tenant(tenant_id)

    def dashboard_counts(self, tenant_id: str) -> dict:
        return {
            "total": self.repo.count_by_tenant(tenant_id),
            "active": self.repo.count_active_by_tenant(tenant_id),
        }
