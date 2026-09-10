"""POST /auth/resend-otp tests.

Resend reads the email + purpose from the secure otp_token cookie, invalidates
the previous OTP, issues a fresh cryptographically secure OTP with a reset
expiry/retry window, replaces the cookie with a new OTP JWT, enforces cooldown
and resend-rate limits, and never returns or logs the code in the response.
"""
from datetime import datetime, timedelta, timezone

from jose import jwt
from sqlalchemy import select

from app.core.config import settings
from app.core.constants import OtpPurpose
from app.db.session import SessionLocal
from app.models.auth import AuthOtp
from app.tests.conftest import set_otp

OTP_COOKIE = "otp_token"


def begin_registration(client, email):
    r = client.post(
        "/auth/register",
        json={
            "full_name": "Person",
            "email": email,
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
            "account_type": "individual",
        },
    )
    assert r.status_code == 201
    return client.cookies.get(OTP_COOKIE)


def otp_rows(email, purpose):
    with SessionLocal() as db:
        return db.scalars(
            select(AuthOtp)
            .where(
                AuthOtp.email == email,
                AuthOtp.purpose == purpose,
            )
            .order_by(AuthOtp.created_at.asc())
        ).all()


def forgot_cookie(client, email):
    r = client.post("/auth/forgot-password", json={"email": email})
    assert r.status_code == 200
    return client.cookies.get(OTP_COOKIE)


def test_resend_otp_success(client, monkeypatch):
    monkeypatch.setattr(settings, "OTP_RESEND_COOLDOWN_SECONDS", 0)
    begin_registration(client, "resend-ok@gmail.com")
    first = client.cookies.get(OTP_COOKIE)

    r = client.post("/auth/resend-otp")
    assert r.status_code == 200
    assert r.json()["message"] == "A new OTP has been sent."
    new_cookie = client.cookies.get(OTP_COOKIE)
    assert new_cookie and new_cookie != first

    rows = otp_rows("resend-ok@gmail.com", OtpPurpose.REGISTRATION.value)
    assert len(rows) == 2
    assert rows[0].revoked_at is not None
    assert rows[1].revoked_at is None


def test_resend_otp_invalidates_previous(client, monkeypatch):
    monkeypatch.setattr(settings, "OTP_RESEND_COOLDOWN_SECONDS", 0)
    begin_registration(client, "resend-invalidate@gmail.com")
    client.post("/auth/resend-otp")

    rows = otp_rows("resend-invalidate@gmail.com", OtpPurpose.REGISTRATION.value)
    assert all(r.revoked_at is not None for r in rows[:-1])
    assert rows[-1].revoked_at is None


def test_resend_otp_new_code_verifies(client, monkeypatch):
    monkeypatch.setattr(settings, "OTP_RESEND_COOLDOWN_SECONDS", 0)
    email = "resend-verify@gmail.com"
    old_cookie = begin_registration(client, email)
    set_otp(email, "111111", purpose="registration")
    client.post("/auth/resend-otp")

    # Old cookie + the current code: cookie/code no longer bound together.
    set_otp(email, "999999", purpose="registration")
    old = client.post(
        "/auth/verify-otp",
        json={"otp": "999999"},
        cookies={OTP_COOKIE: old_cookie},
    )
    assert old.status_code == 400

    # New cookie + new code completes registration.
    fresh = client.post(
        "/auth/verify-otp",
        json={"otp": "999999"},
        cookies={OTP_COOKIE: client.cookies.get(OTP_COOKIE)},
    )
    assert fresh.status_code == 200
    assert fresh.json()["user"]["status"] == "active"


def test_resend_otp_cooldown(client):
    begin_registration(client, "resend-cool@gmail.com")
    r = client.post("/auth/resend-otp")
    assert r.status_code == 429


def test_resend_otp_expired_token(client):
    expired = jwt.encode(
        {
            "sub": "resend-expired@gmail.com",
            "type": "otp",
            "purpose": OtpPurpose.REGISTRATION.value,
            "iat": datetime.now(timezone.utc) - timedelta(minutes=10),
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
            "iss": settings.JWT_ISSUER,
        },
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    r = client.post("/auth/resend-otp", cookies={OTP_COOKIE: expired})
    assert r.status_code == 400


def test_resend_otp_missing_cookie(client):
    assert client.post("/auth/resend-otp").status_code == 400


def test_resend_otp_excessive_attempts(client, monkeypatch):
    monkeypatch.setattr(settings, "OTP_RESEND_COOLDOWN_SECONDS", 0)
    monkeypatch.setattr(settings, "OTP_MAX_RESENDS", 2)
    begin_registration(client, "resend-flood@gmail.com")

    assert client.post("/auth/resend-otp").status_code == 200
    r = client.post("/auth/resend-otp")
    assert r.status_code == 429
    assert "resend" in r.json()["detail"].lower()


def test_resend_otp_never_returns_code(client, monkeypatch):
    monkeypatch.setattr(settings, "OTP_RESEND_COOLDOWN_SECONDS", 0)
    begin_registration(client, "resend-secret@gmail.com")
    r = client.post("/auth/resend-otp")
    assert r.status_code == 200
    assert r.json() == {"message": "A new OTP has been sent."}
    assert not any(part.isdigit() for part in r.text)


def test_resend_forgot_password_purpose(client, monkeypatch):
    monkeypatch.setattr(settings, "OTP_RESEND_COOLDOWN_SECONDS", 0)
    email = "resend-forgot@gmail.com"
    begin_registration(client, email)
    forgot_cookie(client, email)
    assert client.cookies.get(OTP_COOKIE) != ""

    # Old cookie is the forgot-OTP cookie now; resend derives purpose from it.
    r = client.post("/auth/resend-otp", cookies={OTP_COOKIE: client.cookies.get(OTP_COOKIE)})
    assert r.status_code == 200

    set_otp(email, "333333", purpose="forgot_password")
    verify = client.post(
        "/auth/verify-forgot-otp",
        json={"otp": "333333"},
        cookies={OTP_COOKIE: client.cookies.get(OTP_COOKIE)},
    )
    assert verify.status_code == 200


def test_resend_otp_resets_retry_counter(client, monkeypatch):
    monkeypatch.setattr(settings, "OTP_RESEND_COOLDOWN_SECONDS", 0)
    email = "resend-retry@gmail.com"
    begin_registration(client, email)

    set_otp(email, "111111", purpose="registration")
    assert client.post(
        "/auth/verify-otp",
        json={"otp": "000000"},
        cookies={OTP_COOKIE: client.cookies.get(OTP_COOKIE)},
    ).status_code == 400
    assert client.post(
        "/auth/verify-otp",
        json={"otp": "000000"},
        cookies={OTP_COOKIE: client.cookies.get(OTP_COOKIE)},
    ).status_code == 400

    assert client.post("/auth/resend-otp").status_code == 200

    rows = otp_rows(email, OtpPurpose.REGISTRATION.value)
    assert rows[-1].attempt_count == 0

    set_otp(email, "777777", purpose="registration")
    assert client.post(
        "/auth/verify-otp",
        json={"otp": "777777"},
        cookies={OTP_COOKIE: client.cookies.get(OTP_COOKIE)},
    ).status_code == 200