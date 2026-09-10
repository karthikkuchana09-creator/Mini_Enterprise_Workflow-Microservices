from app.core.constants import UserStatus, UserType, UserRole
from app.db.session import SessionLocal
from app.models.user import User
from app.tests.conftest import (
    create_user_direct,
    get_tenant_id,
    register_tenant,
)


def test_register_tenant_creates_tenant_and_admin(client):
    data = register_tenant(client, "boss@acme.com", "hello@acme.com")
    tenant_id = get_tenant_id("hello@acme.com")
    assert data["user"]["role"] == "tenant_admin"
    with SessionLocal() as db:
        u = db.get(User, data["user"]["id"])
        assert u.tenant_id == tenant_id
        assert u.role == UserRole.TENANT_ADMIN


def test_tenant_profile_update_completes(client):
    data = register_tenant(client, "boss2@acme.com", "hi@acme.com")
    access = data["access_token"]
    tenant_id = get_tenant_id("hi@acme.com")
    r = client.patch(
        f"/tenants/{tenant_id}/profile",
        headers={"Authorization": f"Bearer {access}"},
        json={"name": "Acme Corp"},
    )
    assert r.status_code == 200
    assert r.json()["is_complete"] is True
    assert r.json()["profile_completed_at"] is not None


def test_dashboard_counts(client):
    data = register_tenant(client, "boss3@acme.com", "dash@acme.com")
    access = data["access_token"]
    tenant_id = get_tenant_id("dash@acme.com")
    create_user_direct(
        "emp@acme.com", UserType.TENANT_USER, UserRole.TENANT_USER, tenant_id=tenant_id
    )
    # Profiles must be completed before the dashboard is accessible.
    client.patch(
        f"/tenants/{tenant_id}/profile",
        headers={"Authorization": f"Bearer {access}"},
        json={"name": "Acme Corp"},
    )
    r = client.get(
        f"/tenants/{tenant_id}/dashboard",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 200
    assert r.json()["total_users"] == 2
    assert r.json()["active_users"] == 2


def test_invite_user(client):
    data = register_tenant(client, "boss4@acme.com", "inv@acme.com")
    access = data["access_token"]
    tenant_id = get_tenant_id("inv@acme.com")
    r = client.post(
        f"/tenants/{tenant_id}/invitations",
        headers={"Authorization": f"Bearer {access}"},
        json={"email": "newemp@acme.com", "role": "tenant_user"},
    )
    assert r.status_code == 201
    assert r.json()["email"] == "newemp@acme.com"


def test_non_admin_cannot_invite(client):
    data = register_tenant(client, "boss5@acme.com", "noadmin@acme.com")
    tenant_id = get_tenant_id("noadmin@acme.com")
    # Create a tenant_user (not an admin) in the same tenant and mint a token for them
    non_admin_id = create_user_direct(
        "member@acme.com", UserType.TENANT_USER, UserRole.TENANT_USER, tenant_id=tenant_id
    )
    from app.core.security import create_access_token
    token = create_access_token(non_admin_id, UserRole.TENANT_USER.value, tenant_id)
    r = client.post(
        f"/tenants/{tenant_id}/invitations",
        headers={"Authorization": f"Bearer {token}"},
        json={"email": "x@acme.com", "role": "tenant_user"},
    )
    assert r.status_code == 403
