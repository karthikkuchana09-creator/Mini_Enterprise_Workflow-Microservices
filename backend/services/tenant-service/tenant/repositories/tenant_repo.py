from datetime import datetime
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from tenant.security import utcnow

from tenant.constants import TenantStatus, UserRole
from tenant.models.tenant import Tenant, TenantAdmin, TenantInvitation


class TenantRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_tenant(
        self, name: str, org_email: str, status: TenantStatus = TenantStatus.PENDING
    ) -> Tenant:
        tenant = Tenant(name=name, org_email=org_email, status=status)
        self.db.add(tenant)
        self.db.flush()
        if not tenant.tenant_code:
            tenant.tenant_code = self._generate_tenant_code(tenant.id)
            self.db.flush()
        return tenant

    def _generate_tenant_code(self, tenant_id: str) -> str:
        return "T" + tenant_id.replace("-", "")[:12].upper()

    def get_by_id(self, tenant_id: str) -> Optional[Tenant]:
        return self.db.get(Tenant, tenant_id)

    def get_by_org_email(self, org_email: str) -> Optional[Tenant]:
        return self.db.scalar(select(Tenant).where(Tenant.org_email == org_email))

    def add_admin(self, tenant_id: str, user_id: str) -> TenantAdmin:
        admin = TenantAdmin(tenant_id=tenant_id, user_id=user_id)
        self.db.add(admin)
        self.db.flush()
        return admin

    def is_admin(self, tenant_id: str, user_id: str) -> bool:
        return self.db.scalar(
            select(func.count()).select_from(TenantAdmin).where(
                TenantAdmin.tenant_id == tenant_id,
                TenantAdmin.user_id == user_id,
            )
        ) > 0

    def update_tenant(
        self,
        tenant: Tenant,
        name: Optional[str] = None,
        org_email: Optional[str] = None,
        settings: Optional[dict] = None,
        status: Optional[TenantStatus] = None,
        is_complete: Optional[bool] = None,
        profile_completed_at: Optional[datetime] = None,
    ) -> Tenant:
        if name is not None:
            tenant.name = name
        if org_email is not None:
            tenant.org_email = org_email
        if settings is not None:
            tenant.settings = settings
        if status is not None:
            tenant.status = status
        if is_complete is not None:
            tenant.is_complete = is_complete
        if profile_completed_at is not None:
            tenant.profile_completed_at = profile_completed_at
        self.db.flush()
        return tenant

    # Invitations
    def create_invitation(
        self, tenant_id: str, email: str, role: UserRole, token_hash: str, expires_at: datetime
    ) -> TenantInvitation:
        invite = TenantInvitation(
            tenant_id=tenant_id,
            email=email,
            role=role,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        self.db.add(invite)
        self.db.flush()
        return invite

    def get_invitation_by_token(self, token_hash: str) -> Optional[TenantInvitation]:
        return self.db.scalar(
            select(TenantInvitation).where(TenantInvitation.token_hash == token_hash)
        )

    def accept_invitation(self, invite: TenantInvitation) -> None:
        invite.accepted_at = utcnow()
        self.db.flush()

    def count_pending_invitations(self, tenant_id: str) -> int:
        return self.db.scalar(
            select(func.count()).select_from(TenantInvitation).where(
                TenantInvitation.tenant_id == tenant_id,
                TenantInvitation.accepted_at.is_(None),
            )
        ) or 0

    def list_invitations(self, tenant_id: str) -> list[TenantInvitation]:
        return self.db.scalars(
            select(TenantInvitation)
            .where(TenantInvitation.tenant_id == tenant_id)
            .order_by(TenantInvitation.created_at)
        ).all()