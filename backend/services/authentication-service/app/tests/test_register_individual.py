from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.auth import AuthCredentials, AuthOtp
from app.models.user import User
from app.tests.conftest import set_otp


def begin_registration(
    client, email, password="StrongPass1!", full_name="Test User", confirm_password=None
):
    return client.post(
        "/auth/register",
        json={
            "full_name": full_name,
            "email": email,
            "password": password,
            "confirm_password": confirm_password if confirm_password is not None else password,
            "account_type": "individual",
        },
    )


def complete_registration(client, email, otp="111111", otp_token=None, set_code=True):
    if set_code:
        set_otp(email, otp, purpose="registration")
    return client.post(
        "/auth/verify-otp",
        json={"otp": otp},
        cookies={"otp_token": otp_token} if otp_token else {},
    )


def test_register_validates_account_type(client):
    r = client.post(
        "/auth/register",
        json={
            "full_name": "A",
            "email": "a@gmail.com",
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
            "account_type": "organization",
        },
    )
    assert r.status_code == 422


def test_register_requires_account_type(client):
    r = client.post(
        "/auth/register",
        json={
            "full_name": "A",
            "email": "a@gmail.com",
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
        },
    )
    assert r.status_code == 422


def test_register_requires_mandatory_fields(client):
    r = client.post("/auth/register", json={"full_name": "A", "email": "a@gmail.com"})
    assert r.status_code == 422


def test_register_rejects_organization_email(client):
    r = begin_registration(client, "boss@acme-corp.com")
    assert r.status_code == 422
    assert "personal email" in r.json()["detail"].lower()


def test_register_validates_password_policy(client):
    r = begin_registration(client, "weak@gmail.com", password="short")
    assert r.status_code == 422


def test_register_rejects_password_mismatch(client):
    r = begin_registration(
        client, "mismatch@gmail.com", confirm_password="DifferentPass9!"
    )
    assert r.status_code == 422


def test_register_creates_pending_user_sets_otp_cookie(client):
    r = begin_registration(client, "pending@gmail.com")
    assert r.status_code == 201
    body = r.json()
    assert body["message"]
    assert body["email"] == "pending@gmail.com"
    assert body["expires_in"] > 0
    assert "otp_token" in r.cookies

    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "pending@gmail.com"))
        creds = db.scalar(
            select(AuthCredentials).where(AuthCredentials.email == "pending@gmail.com")
        )
        otp = db.scalar(select(AuthOtp).where(AuthOtp.email == "pending@gmail.com"))
    assert user is not None
    assert user.status.value == "pending"
    assert user.role.value == "individual"
    assert user.tenant_id is None
    assert creds is not None
    assert creds.is_active is False
    assert creds.email_verified is False
    assert creds.password_hash != "StrongPass1!"
    assert otp is not None
    assert otp.purpose.value == "registration"


def test_register_duplicate_email_conflict(client):
    begin_registration(client, "dup@gmail.com")
    r = begin_registration(client, "dup@gmail.com", full_name="B")
    assert r.status_code == 409


def test_verify_otp_missing_cookie_rejected(client):
    begin_registration(client, "nocookie@gmail.com")
    r = complete_registration(client, "nocookie@gmail.com", set_code=False)
    assert r.status_code == 400


def test_verify_otp_invalid_cookie_rejected(client):
    r = complete_registration(
        client, "badtoken@gmail.com", otp_token="not-a-jwt", set_code=False
    )
    assert r.status_code == 400


def test_verify_otp_wrong_purpose_rejected(client):
    # issue a forgot_password OTP token instead of a registration one
    from app.core.security import create_otp_token

    token = create_otp_token(user_id="x@gmail.com", purpose="forgot_password", txn="t")
    r = complete_registration(client, "x@gmail.com", otp_token=token, set_code=False)
    assert r.status_code == 400


def test_verify_otp_wrong_code(client):
    r = begin_registration(client, "wrong@gmail.com")
    set_otp("wrong@gmail.com", "999999", purpose="registration")
    resp = client.post(
        "/auth/verify-otp",
        json={"otp": "000000"},
        cookies={"otp_token": r.cookies["otp_token"]},
    )
    assert resp.status_code == 400


def test_verify_otp_max_attempts(client):
    r = begin_registration(client, "maxattempts@gmail.com")
    set_otp("maxattempts@gmail.com", "999999", purpose="registration")
    token = r.cookies["otp_token"]
    for _ in range(3):
        resp = client.post(
            "/auth/verify-otp",
            json={"otp": "000000"},
            cookies={"otp_token": token},
        )
    assert resp.status_code == 429


def test_register_flow_completes_and_allows_login(client):
    r = begin_registration(client, "complete@gmail.com")
    token = r.cookies["otp_token"]
    assert token

    # User cannot log in before OTP verification (pending/inactive).
    pre = client.post(
        "/auth/login",
        json={"email": "complete@gmail.com", "password": "StrongPass1!"},
    )
    assert pre.status_code == 403

    resp = complete_registration(client, "complete@gmail.com", otp_token=token)
    assert resp.status_code == 200
    data = resp.json()
    assert data["access_token"]
    assert data["user"]["email"] == "complete@gmail.com"
    assert data["user"]["status"] == "active"
    assert data["user"]["user_type"] == "individual"
    assert "otp_token" not in resp.cookies

    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "complete@gmail.com"))
        creds = db.scalar(
            select(AuthCredentials).where(AuthCredentials.email == "complete@gmail.com")
        )
    assert user.status.value == "active"
    assert creds.is_active is True
    assert creds.email_verified is True

    post = client.post(
        "/auth/login",
        json={"email": "complete@gmail.com", "password": "StrongPass1!"},
    )
    assert post.status_code == 200
    assert post.json()["user"]["status"] == "active"
