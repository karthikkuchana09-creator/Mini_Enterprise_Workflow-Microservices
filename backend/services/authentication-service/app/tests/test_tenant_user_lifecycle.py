"""End-to-end tenant-user lifecycle tests.

Invite -> accept -> email-OTP activation -> login -> refresh -> logout ->
reuse-rejected, plus single-use invite tokens, invited-email re-registration
protection, and tenant-user (non-admin) capability scoping.
"""
from sqlalchemy import select

from app.core.constants import UserRole, UserStatus, UserType
from app.db.session import SessionLocal
from app.models.auth import AuthCredentials
from app.models.user import User
from app.tests.conftest import register_org_challenge, set_otp
from notification.services.notification_service import notification_service
from tenant.models.tenant import TenantInvitation

PASSWORD = "StrongPass1!"


def _invite(client, monkeypatch, tenant_id, admin_headers, email, role="tenant_user"):
    captured = {}

    def fake_send(email_, tenant_name, invite_token):
        captured["token"] = invite_token

    monkeypatch.setattr(notification_service, "send_invite_email", fake_send)
    r = client.post(
        f"/tenants/{tenant_id}/invitations",
        headers=admin_headers,
        json={"email": email, "role": role},
    )
    assert r.status_code == 201
    return r.json(), captured["token"]


def _activate(client, email, otp="654321"):
    set_otp(email, otp, purpose="email_verify")
    r = client.post(
        "/auth/otp/verify",
        json={"email": email, "otp": otp, "purpose": "email_verify"},
    )
    assert r.status_code == 200
    return r.json()


def test_full_tenant_user_lifecycle(client, monkeypatch):
    org = register_org_challenge(client, "lifeboss@corp.com", "Life Corp")
    tenant_id = org["user"]["tenant_id"]
    admin_headers = {"Authorization": f"Bearer {org['access_token']}"}
    emp_email = "newemployee@corp.com"

    # 1. Admin invites a tenant user; raw token is delivered by email only.
    invite_json, raw_token = _invite(
        client, monkeypatch, tenant_id, admin_headers, emp_email
    )
    assert invite_json["role"] == "tenant_user"
    assert raw_token

    # 2. Invitee accepts; account exists but is pending until email verified.
    accept = client.post(
        "/auth/accept-invitation",
        json={"token": raw_token, "full_name": "New Employee", "password": PASSWORD},
    )
    assert accept.status_code == 201

    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == emp_email))
        assert user is not None
        assert user.role == UserRole.TENANT_USER
        assert user.user_type == UserType.TENANT_USER
        assert user.tenant_id == tenant_id
        assert user.status == UserStatus.PENDING
        creds = db.scalar(
            select(AuthCredentials).where(AuthCredentials.email == emp_email)
        )
        assert creds.is_active is False
        invite = db.scalar(
            select(TenantInvitation).where(TenantInvitation.email == emp_email)
        )
        assert invite is not None
        assert invite.accepted_at is not None

    # 3. Email-OTP activation makes the account usable.
    verified = _activate(client, emp_email)
    assert verified["user"]["status"] == "active"

    # 4. Login works, cookies issued.
    login = client.post(
        "/auth/login", json={"email": emp_email, "password": PASSWORD}
    )
    assert login.status_code == 200
    access1 = login.json()["access_token"]
    refresh1 = login.cookies.get("refresh_token")
    assert refresh1

    # 5. Refresh rotates the pair (new refresh jti; access re-issued).
    refreshed = client.post("/auth/refresh-token")
    assert refreshed.status_code == 200
    assert refreshed.json()["access_token"]
    assert refreshed.cookies.get("refresh_token")
    assert refreshed.cookies.get("refresh_token") != refresh1

    # 6. Logout revokes tokens; reusing the old refresh must fail.
    assert client.post("/auth/logout").status_code == 200
    assert (
        client.post(
            "/auth/refresh-token", cookies={"refresh_token": refresh1}
        ).status_code
        == 401
    )


def test_invite_token_is_single_use(client, monkeypatch):
    org = register_org_challenge(client, "singleboss@corp.com", "Single Use Corp")
    tenant_id = org["user"]["tenant_id"]
    admin_headers = {"Authorization": f"Bearer {org['access_token']}"}
    _, raw_token = _invite(
        client, monkeypatch, tenant_id, admin_headers, "once@corp.com"
    )

    body = {"token": raw_token, "full_name": "Once", "password": PASSWORD}
    assert client.post("/auth/accept-invitation", json=body).status_code == 201
    assert client.post("/auth/accept-invitation", json=body).status_code == 409


def test_invited_email_cannot_register_again(client, monkeypatch):
    org = register_org_challenge(client, "dupempboss@corp.com", "Dup Emp Corp")
    tenant_id = org["user"]["tenant_id"]
    admin_headers = {"Authorization": f"Bearer {org['access_token']}"}
    emp_email = "alreadyinvited@corp.com"
    _, raw_token = _invite(
        client, monkeypatch, tenant_id, admin_headers, emp_email
    )
    assert client.post(
        "/auth/accept-invitation",
        json={"token": raw_token, "full_name": "Dup", "password": PASSWORD},
    ).status_code == 201

    r = client.post(
        "/auth/register",
        json={
            "account_type": "organization",
            "full_name": "Dup",
            "email": emp_email,
            "password": PASSWORD,
            "confirm_password": PASSWORD,
            "organization_name": "Duplicate Inc",
        },
    )
    assert r.status_code == 409


def test_tenant_user_capabilities_are_scoped(client, monkeypatch):
    org = register_org_challenge(client, "scopeboss@corp.com", "Scope Corp")
    tenant_id = org["user"]["tenant_id"]
    admin_headers = {"Authorization": f"Bearer {org['access_token']}"}
    emp_email = "scoped@corp.com"
    _, raw_token = _invite(
        client, monkeypatch, tenant_id, admin_headers, emp_email
    )
    assert client.post(
        "/auth/accept-invitation",
        json={"token": raw_token, "full_name": "Scoped", "password": PASSWORD},
    ).status_code == 201
    activated = _activate(client, emp_email)
    emp_headers = {"Authorization": f"Bearer {activated['access_token']}"}

    assert (
        client.post(
            f"/tenants/{tenant_id}/invitations",
            headers=emp_headers,
            json={"email": "x@corp.com", "role": "tenant_user"},
        ).status_code
        == 403
    )
    assert (
        client.patch(
            f"/tenants/{tenant_id}/profile",
            headers=emp_headers,
            json={"name": "Hijack"},
        ).status_code
        == 403
    )
    assert (
        client.patch(
            f"/tenants/{tenant_id}/status",
            headers=emp_headers,
            json={"status": "active"},
        ).status_code
        == 403
    )
    assert (
        client.get(f"/tenants/{tenant_id}/dashboard", headers=emp_headers).status_code
        == 403
    )
    # A member may read their own organization's public info.
    assert client.get(f"/tenants/{tenant_id}", headers=emp_headers).status_code == 200


def test_tenant_admin_invite_creates_admin_role(client, monkeypatch):
    org = register_org_challenge(client, "secondboss@corp.com", "Co Admin Corp")
    tenant_id = org["user"]["tenant_id"]
    admin_headers = {"Authorization": f"Bearer {org['access_token']}"}
    assert client.patch(
        f"/tenants/{tenant_id}/profile",
        headers=admin_headers,
        json={"name": "Co Admin Corp Official"},
    ).status_code == 200
    co_email = "coadmin@corp.com"
    _, raw_token = _invite(
        client, monkeypatch, tenant_id, admin_headers, co_email, role="tenant_admin"
    )
    assert client.post(
        "/auth/accept-invitation",
        json={"token": raw_token, "full_name": "Co Admin", "password": PASSWORD},
    ).status_code == 201

    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == co_email))
        assert user.role == UserRole.TENANT_ADMIN
        assert user.user_type == UserType.TENANT_ADMIN

    admin2 = _activate(client, co_email)
    headers2 = {"Authorization": f"Bearer {admin2['access_token']}"}
    assert (
        client.get(f"/tenants/{tenant_id}/dashboard", headers=headers2).status_code
        == 200
    )
    # Invited admins gain full admin powers (wired into the tenant admins table).
    assert (
        client.post(
            f"/tenants/{tenant_id}/invitations",
            headers=headers2,
            json={"email": "subuser@corp.com", "role": "tenant_user"},
        ).status_code
        == 201
    )