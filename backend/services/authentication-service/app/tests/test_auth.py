from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.auth import AuthCredentials, AuthOtp, AuthRefreshToken
from app.models.user import User
from app.tests.conftest import register_individual, set_otp


def test_register_individual_creates_pending_user(client):
    client.post(
        "/auth/register/individual",
        json={"email": "a@example.com", "password": "StrongPass1!", "full_name": "A"},
    )
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "a@example.com"))
        creds = db.scalar(select(AuthCredentials).where(AuthCredentials.email == "a@example.com"))
        otp = db.scalar(select(AuthOtp).where(AuthOtp.email == "a@example.com"))
    assert user is not None
    assert user.status.value == "pending"
    assert user.role.value == "individual"
    assert user.tenant_id is None
    assert creds is not None
    assert creds.is_active is False
    assert otp is not None


def test_register_duplicate_email_conflict(client):
    client.post(
        "/auth/register/individual",
        json={"email": "dup@example.com", "password": "StrongPass1!", "full_name": "A"},
    )
    r = client.post(
        "/auth/register/individual",
        json={"email": "dup@example.com", "password": "StrongPass1!", "full_name": "B"},
    )
    assert r.status_code == 409


def test_login_inactive_account_rejected(client):
    client.post(
        "/auth/register/individual",
        json={"email": "in@example.com", "password": "StrongPass1!", "full_name": "A"},
    )
    r = client.post("/auth/login", json={"email": "in@example.com", "password": "StrongPass1!"})
    assert r.status_code == 403


def test_login_wrong_password(client):
    register_individual(client, "login@example.com")
    r = client.post("/auth/login", json={"email": "login@example.com", "password": "WrongPass1!"})
    assert r.status_code == 401


def test_verify_otp_activates_and_returns_tokens(client):
    data = register_individual(client, "verify@example.com")
    assert data["user"]["status"] == "active"
    assert data["access_token"]
    with SessionLocal() as db:
        creds = db.scalar(select(AuthCredentials).where(AuthCredentials.email == "verify@example.com"))
        assert creds.is_active is True
        token_rows = db.scalars(select(AuthRefreshToken)).all()
    assert len(token_rows) == 1


def test_verify_otp_wrong_code(client):
    client.post(
        "/auth/register/individual",
        json={"email": "bad@example.com", "password": "StrongPass1!", "full_name": "A"},
    )
    set_otp("bad@example.com", "999999")
    r = client.post(
        "/auth/otp/verify",
        json={"email": "bad@example.com", "otp": "000000", "purpose": "email_verify"},
    )
    assert r.status_code == 400


def test_refresh_rotates_token(client):
    register_individual(client, "ref@example.com")
    client.post("/auth/login", json={"email": "ref@example.com", "password": "StrongPass1!"})
    r = client.post("/auth/refresh")
    assert r.status_code == 200
    assert r.json()["access_token"]
    with SessionLocal() as db:
        tokens = db.scalars(select(AuthRefreshToken).order_by(AuthRefreshToken.created_at)).all()
    # verify (1) + login (2) then refresh rotates login's -> 3 tokens total
    assert len(tokens) == 3
    assert tokens[1].is_revoked is True
    assert tokens[2].is_revoked is False
    assert tokens[2].rotated_from == tokens[1].id


def test_logout_revokes_refresh_token(client):
    register_individual(client, "out@example.com")
    client.post("/auth/login", json={"email": "out@example.com", "password": "StrongPass1!"})
    client.post("/auth/logout")
    with SessionLocal() as db:
        tokens = db.scalars(select(AuthRefreshToken)).all()
    assert all(t.is_revoked for t in tokens)


def test_forgot_and_reset_password(client):
    register_individual(client, "fp@example.com")
    r = client.post("/auth/forgot-password", json={"email": "fp@example.com"})
    assert r.status_code == 200
    token = r.cookies["otp_token"]
    set_otp("fp@example.com", "222222", "forgot_password")
    r = client.post(
        "/auth/verify-forgot-otp",
        json={"otp": "222222"},
        cookies={"otp_token": token},
    )
    assert r.status_code == 200
    reset = client.cookies["reset_token"]
    r = client.post(
        "/auth/reset-password",
        cookies={"reset_token": reset},
        json={"new_password": "BrandNewPass9!", "confirm_password": "BrandNewPass9!"},
    )
    assert r.status_code == 200
    assert client.post("/auth/login", json={"email": "fp@example.com", "password": "BrandNewPass9!"}).status_code == 200
