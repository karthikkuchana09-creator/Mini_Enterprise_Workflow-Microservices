"""Organization (tenant-admin) authentication flow tests.

Challenge registration -> org created, forgot-password + reset, full session
lifecycle (login/refresh/logout + token reuse rejection), and dashboard gating
until the organization profile is completed.
"""
from sqlalchemy import select

from app.core.constants import UserRole
from app.db.session import SessionLocal
from app.models.user import User
from app.tests.conftest import register_org_challenge, set_otp

PASSWORD = "StrongPass1!"
NEW_PASSWORD = "FreshBossPass2!"


def test_org_admin_forgot_and_reset_password(client):
    email = "resetboss@corp.com"
    org = register_org_challenge(client, email, "Reset Corp")
    admin_headers = {"Authorization": f"Bearer {org['access_token']}"}

    assert client.post("/auth/forgot-password", json={"email": email}).status_code == 200
    set_otp(email, "515151", purpose="forgot_password")
    assert client.post("/auth/verify-forgot-otp", json={"otp": "515151"}).status_code == 200
    reset = client.post(
        "/auth/reset-password",
        json={"new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD},
    )
    assert reset.status_code == 200

    assert client.post(
        "/auth/login", json={"email": email, "password": PASSWORD}
    ).status_code == 401
    login = client.post(
        "/auth/login", json={"email": email, "password": NEW_PASSWORD}
    )
    assert login.status_code == 200

    me = client.get(
        "/users/me", headers={"Authorization": f"Bearer {login.json()['access_token']}"}
    )
    assert me.status_code == 200
    assert me.json()["role"] == UserRole.TENANT_ADMIN.value


def test_org_admin_full_session_lifecycle(client):
    email = "sessionboss@corp.com"
    org = register_org_challenge(client, email, "Session Corp")
    assert org["user"]["role"] == UserRole.TENANT_ADMIN.value

    login = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert login.status_code == 200
    refresh1 = login.cookies.get("refresh_token")
    assert refresh1
    assert login.json()["access_token"]

    refreshed = client.post("/auth/refresh-token")
    assert refreshed.status_code == 200
    assert refreshed.json()["access_token"]
    assert client.cookies.get("refresh_token") != refresh1  # rotation

    assert client.post("/auth/logout").status_code == 200
    assert (
        client.post(
            "/auth/refresh-token", cookies={"refresh_token": refresh1}
        ).status_code
        == 401
    )


def test_org_dashboard_gated_until_profile_completed(client):
    email = "gateboss@corp.com"
    org = register_org_challenge(client, email, "Gate Corp")
    tenant_id = org["user"]["tenant_id"]
    admin_headers = {"Authorization": f"Bearer {org['access_token']}"}

    blocked = client.get(f"/tenants/{tenant_id}/dashboard", headers=admin_headers)
    assert blocked.status_code == 409

    setup = client.patch(
        f"/tenants/{tenant_id}/profile",
        headers=admin_headers,
        json={"name": "Gate Corp Official", "settings": {"industry": "security"}},
    )
    assert setup.status_code == 200
    assert setup.json()["is_complete"] is True

    dash = client.get(f"/tenants/{tenant_id}/dashboard", headers=admin_headers)
    assert dash.status_code == 200
    assert dash.json()["tenant"]["profile_completed_at"] is not None
    assert dash.json()["total_users"] == 1
    assert dash.json()["active_users"] == 1

    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.email == email))
        assert admin.role == UserRole.TENANT_ADMIN
        assert admin.tenant_id == tenant_id