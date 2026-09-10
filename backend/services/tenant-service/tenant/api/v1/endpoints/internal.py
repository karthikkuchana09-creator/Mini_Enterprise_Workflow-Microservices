"""Tenant Service internal API.

Exposes tenant / admin / invitation operations to auth-service over HTTP.
Protected by the shared internal API key (``X-Internal-API-Key`` header).
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from shared.dependencies.internal_auth import create_internal_auth
from tenant.core import tenant_settings
from tenant.database import get_db
from tenant.services.tenant_service import TenantService

router = APIRouter(prefix="/internal", tags=["internal-tenants"])

verify_internal = create_internal_auth(tenant_settings.INTERNAL_API_KEY)


def _tenant_dict(tenant) -> dict:
    return {
        "id": tenant.id,
        "name": tenant.name,
        "tenant_code": getattr(tenant, "tenant_code", None),
        "org_email": tenant.org_email,
        "status": tenant.status.value if hasattr(tenant.status, "value") else tenant.status,
        "is_complete": tenant.is_complete,
        "profile_completed_at": (
            tenant.profile_completed_at.isoformat()
            if tenant.profile_completed_at
            else None
        ),
    }


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


def _invite_dict(invite) -> dict:
    return {
        "id": invite.id,
        "tenant_id": invite.tenant_id,
        "email": invite.email,
        "role": invite.role.value if hasattr(invite.role, "value") else invite.role,
        "expires_at": invite.expires_at.isoformat() if invite.expires_at else None,
        "accepted_at": invite.accepted_at.isoformat() if invite.accepted_at else None,
    }


class TenantCreatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    org_email: EmailStr


class AddAdminPayload(BaseModel):
    user_id: str


class InvitationAcceptPayload(BaseModel):
    token: str
    full_name: str = Field(min_length=1, max_length=255)


@router.post("/tenants", status_code=201)
def internal_create_tenant(
    payload: TenantCreatePayload,
    api_key: str = Depends(verify_internal),
    db: Session = Depends(get_db),
):
    service = TenantService(db)
    service.create_tenant(name=payload.name, org_email=payload.org_email)
    tenant = service.get_tenant_by_org_email(payload.org_email)
    return _tenant_dict(tenant)


@router.get("/tenants/by-org-email/{org_email}")
def internal_get_tenant_by_org_email(
    org_email: str,
    api_key: str = Depends(verify_internal),
    db: Session = Depends(get_db),
):
    tenant = TenantService(db).get_tenant_by_org_email(org_email)
    return _tenant_dict(tenant)


@router.get("/tenants/{tenant_id}")
def internal_get_tenant(
    tenant_id: str,
    api_key: str = Depends(verify_internal),
    db: Session = Depends(get_db),
):
    tenant = TenantService(db).get_tenant(tenant_id)
    return _tenant_dict(tenant)


@router.post("/tenants/{tenant_id}/admins", status_code=201)
def internal_add_admin(
    tenant_id: str,
    payload: AddAdminPayload,
    api_key: str = Depends(verify_internal),
    db: Session = Depends(get_db),
):
    TenantService(db).add_admin(tenant_id, payload.user_id)
    return {"status": "ok"}


@router.post("/tenants/{tenant_id}/activate-account")
def internal_activate_account(
    tenant_id: str,
    api_key: str = Depends(verify_internal),
    db: Session = Depends(get_db),
):
    tenant = TenantService(db).activate_tenant_account(tenant_id)
    return _tenant_dict(tenant)


@router.post("/tenants/invitations/accept", status_code=201)
def internal_accept_invitation(
    payload: InvitationAcceptPayload,
    api_key: str = Depends(verify_internal),
    db: Session = Depends(get_db),
):
    user, invite = TenantService(db).accept_invitation(
        token=payload.token, full_name=payload.full_name
    )
    return {"user": _user_dict(user), "invite": _invite_dict(invite)}