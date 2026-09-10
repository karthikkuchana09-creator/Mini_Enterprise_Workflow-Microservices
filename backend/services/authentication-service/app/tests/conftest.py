import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_otp, hash_password
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.main import app
from app.models.auth import AuthOtp
from app.models.user import User
from app.core.constants import UserRole, UserStatus, UserType
from tenant.models.tenant import Tenant


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c
    Base.metadata.drop_all(bind=engine)


def set_otp(email: str, code: str, purpose: str = "email_verify") -> None:
    with SessionLocal() as db:
        otp = db.scalar(
            select(AuthOtp)
            .where(
                AuthOtp.email == email,
                AuthOtp.purpose == purpose,
                AuthOtp.revoked_at.is_(None),
            )
            .order_by(AuthOtp.created_at.desc())
        )
        otp.otp_hash = hash_otp(code)
        otp.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5)
        db.commit()


def register_individual(client, email, password="StrongPass1!", full_name="Test User", otp="111111"):
    r = client.post(
        "/auth/register/individual",
        json={"email": email, "password": password, "full_name": full_name},
    )
    assert r.status_code == 201
    set_otp(email, otp)
    r = client.post(
        "/auth/otp/verify",
        json={"email": email, "otp": otp, "purpose": "email_verify"},
    )
    assert r.status_code == 200
    return r.json()


def register_tenant(client, email, org_email, otp="333333", password="StrongPass1!"):
    r = client.post(
        "/auth/register/tenant",
        json={
            "email": email,
            "password": password,
            "full_name": "Boss",
            "org_name": "Acme",
            "org_email": org_email,
        },
    )
    assert r.status_code == 201
    set_otp(email, otp)
    r = client.post(
        "/auth/otp/verify",
        json={"email": email, "otp": otp, "purpose": "email_verify"},
    )
    assert r.status_code == 200
    return r.json()


def create_user_direct(email, user_type, role, status=UserStatus.ACTIVE, tenant_id=None):
    with SessionLocal() as db:
        user = User(
            email=email,
            full_name=email,
            user_type=user_type,
            role=role,
            status=status,
            tenant_id=tenant_id,
        )
        db.add(user)
        db.commit()
        return user.id


def get_tenant_id(org_email):
    with SessionLocal() as db:
        return db.scalar(select(Tenant).where(Tenant.org_email == org_email)).id


def begin_challenge(
    client, email, account_type="individual", password="StrongPass1!",
    full_name="Test User", org_name=None,
):
    """Start registration via POST /auth/register (challenge flow).

    Returns (body_json, otp_cookie). Does not verify the OTP.
    """
    body = {
        "account_type": account_type,
        "full_name": full_name,
        "email": email,
        "password": password,
        "confirm_password": password,
    }
    if org_name:
        body["organization_name"] = org_name
    r = client.post("/auth/register", json=body)
    assert r.status_code == 201
    return r.json(), client.cookies.get("otp_token")


def verify_challenge(client, email, otp="111111"):
    """Complete registration with a known OTP via POST /auth/verify-otp."""
    set_otp(email, otp, purpose="registration")
    r = client.post("/auth/verify-otp", json={"otp": otp})
    assert r.status_code == 200
    return r.json()


def register_individual_challenge(client, email, otp="111111", password="StrongPass1!"):
    begin_challenge(client, email, account_type="individual", password=password)
    return verify_challenge(client, email, otp=otp)


def register_org_challenge(client, email, org_name="Acme Inc", otp="111111", password="StrongPass1!"):
    begin_challenge(
        client, email, account_type="organization", org_name=org_name, password=password
    )
    return verify_challenge(client, email, otp=otp)
