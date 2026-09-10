from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.auth import AuthCredentials
from app.models.user import User
from app.tests.conftest import set_otp
from tenant.models.tenant import Tenant, TenantAdmin


def begin_org(client, email, org_name="Acme Corp", password="StrongPass1!"):
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


def set_otp_expired(email):
    with SessionLocal() as db:
        from app.models.auth import AuthOtp

        otp = db.scalar(
            select(AuthOtp)
            .where(AuthOtp.email == email, AuthOtp.revoked_at.is_(None))
            .order_by(AuthOtp.created_at.desc())
        )
        otp.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
            minutes=1
        )
        db.commit()


def verify_org(client, email, otp="111111", otp_token=None, set_code=True):
    if set_code:
        set_otp(email, otp, purpose="registration")
    return client.post(
        "/auth/verify-otp",
        json={"otp": otp},
        cookies={"otp_token": otp_token} if otp_token else {},
    )


def fetch_org(email):
    with SessionLocal() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.org_email == email))
        user = db.scalar(select(User).where(User.email == email))
        admin = (
            db.scalar(
                select(TenantAdmin).where(TenantAdmin.user_id == user.id)
            )
            if user
            else None
        )
        creds = db.scalar(
            select(AuthCredentials).where(AuthCredentials.email == email)
        )
        return tenant, user, admin, creds


def test_register_valid_organization_flow(client):
    r = begin_org(client, "ceo@acme-corp.com")
    assert r.status_code == 201
    assert r.json()["email"] == "ceo@acme-corp.com"
    assert "otp_token" in r.cookies

    tenant, user, admin, creds = fetch_org("ceo@acme-corp.com")
    assert tenant is not None
    assert tenant.status.value == "pending"
    assert tenant.is_complete is False
    assert user is not None
    assert user.status.value == "pending"
    assert user.tenant_id == tenant.id
    assert admin is not None
    assert user.user_type.value == "tenant_admin"
    assert user.role.value == "tenant_admin"
    assert creds is not None
    assert creds.is_active is False


def test_complete_org_registration_activates_tenant_and_admin(client):
    r = begin_org(client, "boss@globex.io")
    token = r.cookies["otp_token"]

    pre = client.post(
        "/auth/login",
        json={"email": "boss@globex.io", "password": "StrongPass1!"},
    )
    assert pre.status_code == 403

    resp = verify_org(client, "boss@globex.io", otp_token=token)
    assert resp.status_code == 200
    data = resp.json()
    assert data["access_token"]
    assert data["user"]["status"] == "active"
    assert data["user"]["user_type"] == "tenant_admin"
    assert "otp_token" not in resp.cookies

    tenant, user, admin, creds = fetch_org("boss@globex.io")
    assert tenant.status.value == "active"
    assert tenant.is_complete is True
    assert user.status.value == "active"
    assert creds.is_active is True
    assert creds.email_verified is True

    post = client.post(
        "/auth/login",
        json={"email": "boss@globex.io", "password": "StrongPass1!"},
    )
    assert post.status_code == 200


def test_register_rejects_personal_email(client):
    r = begin_org(client, "ceo@gmail.com")
    assert r.status_code == 422


def test_register_duplicate_email(client):
    begin_org(client, "dup@corp.com")
    r = begin_org(client, "dup@corp.com")
    assert r.status_code == 409


def test_register_missing_organization_name(client):
    r = begin_org(client, "nona@corp.com", org_name="   ")
    assert r.status_code == 422


def test_register_password_mismatch(client):
    r = client.post(
        "/auth/register",
        json={
            "full_name": "Boss",
            "email": "boss@corp.com",
            "organization_name": "Acme",
            "password": "StrongPass1!",
            "confirm_password": "DifferentPass9!",
            "account_type": "organization",
        },
    )
    assert r.status_code == 422


def test_register_invalid_account_type(client):
    r = client.post(
        "/auth/register",
        json={
            "full_name": "Boss",
            "email": "boss@corp.com",
            "organization_name": "Acme",
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
            "account_type": "individual",
        },
    )
    assert r.status_code == 422


def test_verify_otp_invalid_code(client):
    r = begin_org(client, "bad@corp.com")
    token = r.cookies["otp_token"]
    set_otp("bad@corp.com", "999999", purpose="registration")
    resp = client.post(
        "/auth/verify-otp",
        json={"otp": "000000"},
        cookies={"otp_token": token},
    )
    assert resp.status_code == 400
    tenant, user, _, _ = fetch_org("bad@corp.com")
    assert tenant.status.value == "pending"
    assert user.status.value == "pending"


def test_verify_otp_expired_code(client):
    r = begin_org(client, "exp@corp.com")
    set_otp_expired("exp@corp.com")
    resp = client.post(
        "/auth/verify-otp",
        json={"otp": "111111"},
        cookies={"otp_token": r.cookies["otp_token"]},
    )
    assert resp.status_code == 400
    tenant, user, _, _ = fetch_org("exp@corp.com")
    assert tenant.status.value == "pending"
    assert user.status.value == "pending"


def test_register_missing_otp_cookie(client):
    begin_org(client, "nocookie@corp.com")
    r = verify_org(client, "nocookie@corp.com", otp_token=None, set_code=False)
    assert r.status_code == 400


def test_tenant_admin_relationship(client):
    begin_org(client, "rel@corp.com")
    r = verify_org(client, "rel@corp.com", otp_token="jwt")
    tenant, user, admin, _ = fetch_org("rel@corp.com")
    assert tenant is not None
    assert user is not None
    assert user.tenant_id == tenant.id
    assert admin is not None
    assert admin.tenant_id == tenant.id
    assert admin.user_id == user.id


def test_activation_failure_rolls_back_consistently(client, monkeypatch):
    r = begin_org(client, "rollback@corp.com")
    assert r.status_code == 201
    token = r.cookies["otp_token"]
    set_otp("rollback@corp.com", "111111", purpose="registration")

    # The last activation step (mark email verified) fails, forcing a rollback
    # of the whole verify-otp transaction so neither tenant nor user is left
    # half-activated.
    from app.repositories.auth_repo import AuthRepository

    def boom(self, user_id):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(AuthRepository, "mark_email_verified", boom)

    with pytest.raises(RuntimeError):
        client.post(
            "/auth/verify-otp",
            json={"otp": "111111"},
            cookies={"otp_token": token},
        )

    tenant, user, _, creds = fetch_org("rollback@corp.com")
    assert tenant.status.value == "pending"
    assert tenant.is_complete is False
    assert user.status.value == "pending"
    assert creds.is_active is False
    assert creds.email_verified is False
