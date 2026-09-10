import secrets
from datetime import timedelta
from typing import Optional

from sqlalchemy.orm import Session

from app.core.emails import validate_organization_email
from tenant.constants import TenantStatus, UserRole, UserStatus, UserType
from tenant.core import tenant_settings
from tenant.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError_,
)
from tenant.notify import notification_service
from tenant.repositories.tenant_repo import TenantRepository
from tenant.security import hash_jti, utcnow


class TenantService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = TenantRepository(db)
        if tenant_settings.SERVICE_MODE == "microservices":
            # Users live in the auth-service database; reach them over HTTP.
            from shared.clients.auth_client import AuthClient

            self.user_service = AuthClient(
                base_url=tenant_settings.AUTH_SERVICE_URL,
                api_key=tenant_settings.INTERNAL_API_KEY,
            )
        else:
            # Monolith mode: the auth-service in-process service (shared DB).
            from app.services.user_service import UserService

            self.user_service = UserService(db)

    def create_tenant(self, name: str, org_email: str) -> None:
        if self.repo.get_by_org_email(org_email):
            raise ConflictError("Organization email already registered")
        self.repo.create_tenant(name=name, org_email=org_email, status=TenantStatus.PENDING)

    def add_admin(self, tenant_id: str, user_id: str) -> None:
        if not self.repo.get_by_id(tenant_id):
            raise NotFoundError("Tenant not found")
        self.repo.add_admin(tenant_id=tenant_id, user_id=user_id)

    def get_tenant(self, tenant_id: str):
        tenant = self.repo.get_by_id(tenant_id)
        if not tenant:
            raise NotFoundError("Tenant not found")
        return tenant

    def get_tenant_by_org_email(self, org_email: str):
        tenant = self.repo.get_by_org_email(org_email)
        if not tenant:
            raise NotFoundError("Tenant not found")
        return tenant

    def update_profile(self, tenant_id: str, name=None, org_email=None, settings_=None):
        tenant = self.get_tenant(tenant_id)
        first_completion = tenant.profile_completed_at is None
        if org_email is not None:
            org_email = validate_organization_email(org_email)
        updated = self.repo.update_tenant(
            tenant, name=name, org_email=org_email, settings=settings_
        )
        # Completing the organization profile records the timestamp; the
        # dashboard stays gated until profile_completed_at is set.
        updated = self.repo.update_tenant(
            updated, is_complete=True, profile_completed_at=utcnow()
        )
        if first_completion:
            notification_service.send_profile_completion_email(
                updated.org_email or tenant.org_email, updated.name
            )
        return updated

    def activate(self, tenant_id: str):
        tenant = self.get_tenant(tenant_id)
        return self.repo.update_tenant(tenant, status=TenantStatus.ACTIVE)

    def activate_tenant_account(self, tenant_id: str):
        """Activate an Organization account after registration verification.

        Business rule: an Organization tenant becomes ACTIVE and is marked
        profile-complete once its admin's email is verified.
        """
        tenant = self.get_tenant(tenant_id)
        return self.repo.update_tenant(
            tenant, status=TenantStatus.ACTIVE, is_complete=True
        )

    def deactivate(self, tenant_id: str):
        tenant = self.get_tenant(tenant_id)
        return self.repo.update_tenant(tenant, status=TenantStatus.INACTIVE)

    def update_status(self, tenant_id: str, status: TenantStatus):
        tenant = self.get_tenant(tenant_id)
        return self.repo.update_tenant(tenant, status=status)

    def create_invitation(self, tenant_id: str, email: str, role: UserRole, admin_user_id: str):
        if not self.repo.is_admin(tenant_id, admin_user_id):
            raise ForbiddenError("Only tenant admins can invite users")
        if role not in (UserRole.TENANT_USER, UserRole.TENANT_ADMIN):
            raise ValidationError_("Invalid invitation role")
        if self.user_service.get_by_email(email):
            raise ConflictError("A user with this email already exists")
        jti = secrets.token_hex(24)
        token_hash = hash_jti(jti)
        expires_at = utcnow() + timedelta(days=7)
        invite = self.repo.create_invitation(
            tenant_id=tenant_id,
            email=email,
            role=role,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        return invite, jti

    def accept_invitation(self, token: str, full_name: str):
        token_hash = hash_jti(token)
        invite = self.repo.get_invitation_by_token(token_hash)
        if not invite:
            raise NotFoundError("Invitation not found or already used")
        if invite.accepted_at is not None:
            raise ConflictError("Invitation already accepted")
        if invite.expires_at < utcnow():
            raise ValidationError_("Invitation has expired")

        if self.user_service.get_by_email(invite.email):
            raise ConflictError("User already registered")

        user_type = (
            UserType.TENANT_ADMIN if invite.role == UserRole.TENANT_ADMIN
            else UserType.TENANT_USER
        )
        user = self.user_service.create_user(
            email=invite.email,
            full_name=full_name,
            user_type=user_type,
            role=invite.role,
            status=UserStatus.PENDING,
            tenant_id=invite.tenant_id,
        )

        if invite.role == UserRole.TENANT_ADMIN:
            self.repo.add_admin(invite.tenant_id, user.id)

        self.repo.accept_invitation(invite)
        tenant = self.repo.get_by_id(invite.tenant_id)
        notification_service.send_invitation_accepted_email(
            invite.email, tenant.name if tenant else "your organization"
        )
        return user, invite

    def list_invitations(self, tenant_id: str, admin_user_id: str):
        if not self.repo.is_admin(tenant_id, admin_user_id):
            raise ForbiddenError("Only tenant admins can view invitations")
        return self.repo.list_invitations(tenant_id)

    def pending_invitations_count(self, tenant_id: str) -> int:
        return self.repo.count_pending_invitations(tenant_id)

    def dashboard(self, tenant_id: str, admin_user_id: str) -> dict:
        if not self.repo.is_admin(tenant_id, admin_user_id):
            raise ForbiddenError("Only tenant admins can view dashboard")
        tenant = self.get_tenant(tenant_id)
        if tenant.profile_completed_at is None:
            raise ConflictError(
                "Complete the organization profile to access the dashboard"
            )
        counts = self.user_service.dashboard_counts(tenant_id)
        return {
            "tenant": tenant,
            "total_users": counts["total"],
            "active_users": counts["active"],
            "pending_invitations": self.repo.count_pending_invitations(tenant_id),
        }