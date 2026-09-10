from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from tenant.constants import UserRole
from tenant.database import get_db
from tenant.dependencies import (
    get_current_user,
    require_role,
    require_tenant,
)
from tenant.notify import notification_service
from tenant.schemas.tenant import (
    DashboardResponse,
    TenantBase,
    TenantInvitationResponse,
    TenantInviteRequest,
    TenantProfileUpdate,
    TenantStatusUpdate,
)
from tenant.services.tenant_service import TenantService

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.get("/{tenant_id}", response_model=TenantBase)
def get_tenant(
    tenant_id: str,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_tenant(tenant_id, user=user)
    tenant = TenantService(db).get_tenant(tenant_id)
    return TenantBase(
        id=tenant.id,
        name=tenant.name,
        org_email=tenant.org_email,
        status=tenant.status,
        is_complete=tenant.is_complete,
        profile_completed_at=tenant.profile_completed_at,
    )


@router.patch("/{tenant_id}/profile", response_model=TenantBase)
def update_tenant_profile(
    tenant_id: str,
    payload: TenantProfileUpdate,
    user=Depends(require_role(UserRole.TENANT_ADMIN)),
    db: Session = Depends(get_db),
):
    require_tenant(tenant_id, user=user)
    tenant = TenantService(db).update_profile(
        tenant_id,
        name=payload.name,
        org_email=str(payload.org_email) if payload.org_email else None,
        settings_=payload.settings,
    )
    return TenantBase(
        id=tenant.id,
        name=tenant.name,
        org_email=tenant.org_email,
        status=tenant.status,
        is_complete=tenant.is_complete,
        profile_completed_at=tenant.profile_completed_at,
    )


@router.patch("/{tenant_id}/status", response_model=TenantBase)
def update_tenant_status(
    tenant_id: str,
    payload: TenantStatusUpdate,
    user=Depends(require_role(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
):
    if user.role != UserRole.SUPER_ADMIN:
        require_tenant(tenant_id, user=user)
    tenant = TenantService(db).update_status(tenant_id, payload.status)
    return TenantBase(
        id=tenant.id,
        name=tenant.name,
        org_email=tenant.org_email,
        status=tenant.status,
        is_complete=tenant.is_complete,
        profile_completed_at=tenant.profile_completed_at,
    )


@router.post("/{tenant_id}/invitations", response_model=TenantInvitationResponse, status_code=201)
def invite_user(
    tenant_id: str,
    payload: TenantInviteRequest,
    user=Depends(require_role(UserRole.TENANT_ADMIN)),
    db: Session = Depends(get_db),
):
    service = TenantService(db)
    invite, raw_token = service.create_invitation(
        tenant_id, str(payload.email), payload.role, admin_user_id=user.id
    )
    notification_service.send_invite_email(str(payload.email), service.get_tenant(tenant_id).name, raw_token)
    return TenantInvitationResponse(
        id=invite.id,
        tenant_id=invite.tenant_id,
        email=invite.email,
        role=invite.role.value,
        expires_at=invite.expires_at,
        accepted_at=invite.accepted_at,
    )


@router.get("/{tenant_id}/invitations", response_model=list[TenantInvitationResponse])
def list_invitations(
    tenant_id: str,
    user=Depends(require_role(UserRole.TENANT_ADMIN)),
    db: Session = Depends(get_db),
):
    invites = TenantService(db).list_invitations(tenant_id, admin_user_id=user.id)
    return [
        TenantInvitationResponse(
            id=i.id,
            tenant_id=i.tenant_id,
            email=i.email,
            role=i.role.value,
            expires_at=i.expires_at,
            accepted_at=i.accepted_at,
        )
        for i in invites
    ]


@router.get("/{tenant_id}/dashboard", response_model=DashboardResponse)
def tenant_dashboard(
    tenant_id: str,
    user=Depends(require_role(UserRole.TENANT_ADMIN)),
    db: Session = Depends(get_db),
):
    data = TenantService(db).dashboard(tenant_id, admin_user_id=user.id)
    tenant = data["tenant"]
    return DashboardResponse(
        tenant=TenantBase(
            id=tenant.id,
            name=tenant.name,
            org_email=tenant.org_email,
            status=tenant.status,
            is_complete=tenant.is_complete,
            profile_completed_at=tenant.profile_completed_at,
        ),
        total_users=data["total_users"],
        active_users=data["active_users"],
        pending_invitations=data["pending_invitations"],
    )