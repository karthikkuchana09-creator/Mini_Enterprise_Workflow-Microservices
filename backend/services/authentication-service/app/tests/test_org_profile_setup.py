"""Organization User Signup/Profile Setup workflow tests.

Covers the post-registration Organization Profile Setup: signup -> OTP
verification -> tenant/admin created -> profile setup -> profile completed ->
tenant admin dashboard (gated until the profile setup is completed).
"""
import pytest
from sqlalchemy import select

from app.core.constants import UserRole, UserStatus, UserType
from app.core.exceptions import ConflictError
from app.core.security import create_access_token
from app.db.session import SessionLocal
from app.services.user_service import UserService
from app.tests.conftest import create_user_direct, set_otp
from tenant.models.tenant import Tenant
from tenant.repositories.tenant_repo import TenantRepository
from tenant.services.tenant_service import TenantService


def begin_org(client, email, org_name="Profile Corp", password="StrongPass1!"):
    return client.post(
        "/auth/register",
        json={
            "full_name": "Boss",
            "email": email,
            "organization_name": org_name,
            "password": password,
            "confirm_password": password,
            "account_type": "organization",
        },
    )


def complete_registration(client, email, otp="111111"):
    r = begin_org(client, email)
    assert r.status_code == 201
    token = r.cookies["otp_token"]
    set_otp(email, otp, purpose="registration")
    resp = client.post(
        "/auth/verify-otp",
        json={"otp": otp},
        cookies={"otp_token": token},
    )
    return resp, token


def get_tenant_id(org_email):
    with SessionLocal() as db:
        return db.scalar(select(Tenant).where(Tenant.org_email == org_email)).id


def profile_setup(client, tenant_id, access, payload, status=200):
    return client.patch(
        f"/tenants/{tenant_id}/profile",
        headers={"Authorization": f"Bearer {access}"},
        json=payload,
    )


def test_org_profile_setup_full_flow(client):
    email = "boss@profiledemo.io"
    resp, _ = complete_registration(client, email)
    assert resp.status_code == 200
    assert resp.json()["user"]["status"] == "active"

    tenant_id = get_tenant_id(email)
    access = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {access}"}

    # 1. Dashboard is gated until the organization profile is completed.
    blocked = client.get(f"/tenants/{tenant_id}/dashboard", headers=headers)
    assert blocked.status_code == 409

    # 2. Organization Profile Setup (reuses the existing profile endpoint/fields).
    setup = profile_setup(
        client,
        tenant_id,
        access,
        {"name": "Profile Demo Corp", "settings": {"industry": "tech"}},
    )
    assert setup.status_code == 200
    assert setup.json()["is_complete"] is True
    assert setup.json()["profile_completed_at"] is not None

    # 3. Tenant Admin Dashboard now accessible with data.
    dash = client.get(f"/tenants/{tenant_id}/dashboard", headers=headers)
    assert dash.status_code == 200
    body = dash.json()
    assert body["tenant"]["profile_completed_at"] is not None
    assert body["total_users"] == 1
    assert body["active_users"] == 1
    assert body["pending_invitations"] == 0

    # 4. Persisted final state: tenant + admin + verified + profile completed.
    with SessionLocal() as db:
        tenant = db.get(Tenant, tenant_id)
        assert tenant.status.value == "active"
        assert tenant.is_complete is True
        assert tenant.profile_completed_at is not None


def test_org_profile_setup_rejects_personal_email(client):
    email = "boss@setupcheck.io"
    resp, _ = complete_registration(client, email)
    tenant_id = get_tenant_id(email)
    access = resp.json()["access_token"]

    r = profile_setup(
        client,
        tenant_id,
        access,
        {"org_email": "admin@gmail.com"},
        status=None,
    )
    assert r.status_code == 422

    with SessionLocal() as db:
        tenant = db.get(Tenant, tenant_id)
        assert tenant.org_email == email
        assert tenant.profile_completed_at is None
        assert tenant.is_complete is True


def test_org_profile_endpoint_requires_admin(client):
    email = "boss@profileadminck.io"
    resp, _ = complete_registration(client, email)
    tenant_id = get_tenant_id(email)

    non_admin_id = create_user_direct(
        "member@profileadminck.io",
        UserType.TENANT_USER,
        UserRole.TENANT_USER,
        tenant_id=tenant_id,
    )
    member_token = create_access_token(
        non_admin_id, UserRole.TENANT_USER.value, tenant_id
    )
    r = client.patch(
        f"/tenants/{tenant_id}/profile",
        headers={"Authorization": f"Bearer {member_token}"},
        json={"name": "Hijack"},
    )
    assert r.status_code == 403


def test_tenant_service_dashboard_gated_and_profile_completion(client):
    """Service-level coverage: dashboard is gated and update_profile completes it."""
    email = "unit@svcdemo.io"
    with SessionLocal() as db:
        repo = TenantRepository(db)
        tenant = repo.create_tenant(name="Unit Corp", org_email=email)
        user = UserService(db).create_user(
            email=email,
            full_name="Boss",
            user_type=UserType.TENANT_ADMIN,
            role=UserRole.TENANT_ADMIN,
            status=UserStatus.ACTIVE,
            tenant_id=tenant.id,
        )
        repo.add_admin(tenant.id, user.id)
        service = TenantService(db)

        with pytest.raises(ConflictError):
            service.dashboard(tenant.id, user.id)

        updated = service.update_profile(tenant.id, name="Unit Corp Updated")
        assert updated.profile_completed_at is not None
        assert updated.is_complete is True

        data = service.dashboard(tenant.id, user.id)
        assert data["tenant"].id == tenant.id
        assert data["total_users"] == 1
        assert data["active_users"] == 1
        db.rollback()