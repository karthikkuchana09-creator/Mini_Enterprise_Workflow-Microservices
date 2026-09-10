"""Forgot-password flow tests.

Covers POST /auth/forgot-password, POST /auth/verify-forgot-otp, and
POST /auth/reset-password: OTP issuance (purpose=forgot_password), the
otp_token cookie, enumeration resistance, OTP verification (purpose/expiry/
retry count), secure password-reset state establishment, cookie clearing, and
server-side session invalidation on reset.
"""
from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt
from sqlalchemy import select

from app.core.config import settings
from app.core.constants import OtpPurpose, UserRole, UserStatus, UserType
from app.core.exceptions import OtpInvalidError
from app.core.security import create_otp_token, hash_password, verify_password
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models.auth import AuthCredentials, AuthOtp, AuthRefreshToken
from app.repositories.auth_repo import AuthRepository
from app.services.auth_service import AuthService
from app.services.user_service import UserService
from app.tests.conftest import set_otp

OTP_COOKIE = "otp_token"
RESET_COOKIE = settings.RESET_TOKEN_COOKIE_NAME


@pytest.fixture()
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def register_verified(client, email, otp="111111"):
    r = client.post(
        "/auth/register",
        json={
            "full_name": "Person",
            "email": email,
            "password": "OldPass1!",
            "confirm_password": "OldPass1!",
            "account_type": "individual",
        },
    )
    assert r.status_code == 201
    token = r.cookies[OTP_COOKIE]
    set_otp(email, otp, purpose="registration")
    assert client.post(
        "/auth/verify-otp",
        json={"otp": otp},
        cookies={OTP_COOKIE: token},
    ).status_code == 200


def begin_forgot(client, email):
    return client.post("/auth/forgot-password", json={"email": email})


def verify_code(client, code, otp_token):
    return client.post(
        "/auth/verify-forgot-otp",
        json={"otp": code},
        cookies={OTP_COOKIE: otp_token},
    )


def reset_password(client, reset_token=None, new_password="NewPass9!", confirm=None):
    kwargs = {}
    if reset_token:
        kwargs["cookies"] = {RESET_COOKIE: reset_token}
    return client.post(
        "/auth/reset-password",
        json={
            "new_password": new_password,
            "confirm_password": confirm if confirm is not None else new_password,
        },
        **kwargs,
    )


def make_active_user(email, password="OldPass1!"):
    with SessionLocal() as db:
        user = UserService(db).create_user(
            email=email,
            full_name="User",
            user_type=UserType.INDIVIDUAL,
            role=UserRole.INDIVIDUAL,
            status=UserStatus.ACTIVE,
        )
        AuthRepository(db).create_credentials(
            user_id=user.id,
            email=email,
            password_hash=hash_password(password),
            is_active=True,
        )
        db.commit()
        return user.id


def active_otp(email, purpose):
    with SessionLocal() as db:
        return db.scalar(
            select(AuthOtp).where(
                AuthOtp.email == email,
                AuthOtp.purpose == purpose,
            )
        )


# ---------------------------------------------------------------------------
# POST /auth/forgot-password
# ---------------------------------------------------------------------------
def test_forgot_password_sets_otp_cookie_and_issues_otp(client):
    register_verified(client, "forgot@gmail.com")
    r = begin_forgot(client, "forgot@gmail.com")
    assert r.status_code == 200
    assert r.json()["message"] == "If the email exists, a reset OTP has been sent."
    assert client.cookies.get(OTP_COOKIE)

    otp = active_otp("forgot@gmail.com", OtpPurpose.FORGOT_PASSWORD.value)
    assert otp is not None
    assert otp.revoked_at is None
    assert "forgot@gmail.com" not in str(otp.otp_hash)


def test_forgot_password_unknown_email_does_not_enumerate(client):
    known = begin_forgot(client, "forgot@gmail.com")
    unknown = begin_forgot(client, "ghost@gmail.com")
    assert known.status_code == 200
    assert unknown.status_code == 200
    assert known.json() == unknown.json()
    assert unknown.cookies.get(OTP_COOKIE) is None


def test_forgot_password_unknown_email_stores_no_otp(client):
    begin_forgot(client, "ghost@gmail.com")
    assert active_otp("ghost@gmail.com", OtpPurpose.FORGOT_PASSWORD.value) is None


# ---------------------------------------------------------------------------
# POST /auth/verify-forgot-otp
# ---------------------------------------------------------------------------
def test_verify_forgot_otp_establishes_reset_state(client):
    register_verified(client, "verify@gmail.com")
    otp_token = begin_forgot(client, "verify@gmail.com").cookies.get(OTP_COOKIE)
    set_otp("verify@gmail.com", "333333", purpose="forgot_password")

    r = verify_code(client, "333333", otp_token)
    assert r.status_code == 200
    assert "OTP verified" in r.json()["message"]
    assert client.cookies.get(OTP_COOKIE) is None
    assert client.cookies.get(RESET_COOKIE)

    otp = active_otp("verify@gmail.com", OtpPurpose.FORGOT_PASSWORD.value)
    assert otp.revoked_at is not None


def test_verify_forgot_otp_wrong_code(client):
    register_verified(client, "wrong@gmail.com")
    otp_token = begin_forgot(client, "wrong@gmail.com").cookies.get(OTP_COOKIE)
    set_otp("wrong@gmail.com", "333333", purpose="forgot_password")
    assert verify_code(client, "000000", otp_token).status_code == 400


def test_verify_forgot_otp_missing_cookie(client):
    register_verified(client, "nocookie@gmail.com")
    otp_token = begin_forgot(client, "nocookie@gmail.com").cookies.get(OTP_COOKIE)
    set_otp("nocookie@gmail.com", "333333", purpose="forgot_password")
    client.cookies.clear()
    r = client.post("/auth/verify-forgot-otp", json={"otp": "333333"})
    assert r.status_code == 400


def test_verify_forgot_otp_wrong_purpose_token(client):
    register_verified(client, "purpose@gmail.com")
    # registration-purpose token must not unlock the forgot-password flow
    begin_forgot(client, "purpose@gmail.com")
    set_otp("purpose@gmail.com", "333333", purpose="forgot_password")
    reg_token = create_otp_token(
        "purpose@gmail.com", OtpPurpose.REGISTRATION.value, "txn"
    )
    assert verify_code(client, "333333", reg_token).status_code == 400


def test_verify_forgot_otp_respects_retry_limit(client):
    register_verified(client, "retry@gmail.com")
    otp_token = begin_forgot(client, "retry@gmail.com").cookies.get(OTP_COOKIE)
    set_otp("retry@gmail.com", "333333", purpose="forgot_password")

    assert verify_code(client, "000000", otp_token).status_code == 400
    assert verify_code(client, "000000", otp_token).status_code == 400
    assert verify_code(client, "000000", otp_token).status_code == 429


def test_verify_forgot_otp_skips_mismatched_txn(client):
    register_verified(client, "txn@gmail.com")
    begin_forgot(client, "txn@gmail.com")
    set_otp("txn@gmail.com", "333333", purpose="forgot_password")
    code_token = create_otp_token(
        "txn@gmail.com", OtpPurpose.FORGOT_PASSWORD.value, "bogus-txn"
    )
    assert verify_code(client, "333333", code_token).status_code == 400


# ---------------------------------------------------------------------------
# POST /auth/reset-password
# ---------------------------------------------------------------------------
def test_reset_password_full_flow(client):
    register_verified(client, "flow@gmail.com")
    assert client.post(
        "/auth/login", json={"email": "flow@gmail.com", "password": "OldPass1!"}
    ).status_code == 200

    otp_token = begin_forgot(client, "flow@gmail.com").cookies.get(OTP_COOKIE)
    set_otp("flow@gmail.com", "333333", purpose="forgot_password")
    assert verify_code(client, "333333", otp_token).status_code == 200
    reset = client.cookies.get(RESET_COOKIE)

    r = reset_password(client, reset_token=reset, new_password="NewPass9!")
    assert r.status_code == 200
    assert r.json()["message"] == "Password reset successfully."
    assert client.cookies.get(RESET_COOKIE) is None

    assert client.post(
        "/auth/login", json={"email": "flow@gmail.com", "password": "NewPass9!"}
    ).status_code == 200
    assert client.post(
        "/auth/login", json={"email": "flow@gmail.com", "password": "OldPass1!"}
    ).status_code == 401


def test_reset_password_revokes_refresh_tokens(client):
    register_verified(client, "rotatefree@gmail.com")
    client.post(
        "/auth/login", json={"email": "rotatefree@gmail.com", "password": "OldPass1!"}
    )
    old_refresh = client.cookies.get(settings.REFRESH_TOKEN_COOKIE_NAME)

    otp_token = begin_forgot(client, "rotatefree@gmail.com").cookies.get(OTP_COOKIE)
    set_otp("rotatefree@gmail.com", "333333", purpose="forgot_password")
    assert verify_code(client, "333333", otp_token).status_code == 200
    reset = client.cookies.get(RESET_COOKIE)
    reset_password(client, reset_token=reset, new_password="NewPass9!")

    with SessionLocal() as db:
        tokens = db.scalars(select(AuthRefreshToken)).all()
    assert tokens
    assert all(t.is_revoked for t in tokens)

    assert client.post(
        "/auth/refresh-token",
        cookies={settings.REFRESH_TOKEN_COOKIE_NAME: old_refresh},
    ).status_code == 401


def test_reset_password_requires_valid_state(client):
    register_verified(client, "state@gmail.com")
    assert reset_password(client).status_code == 400


def test_reset_password_rejects_mismatched_confirmation(client):
    register_verified(client, "mismatch@gmail.com")
    otp_token = begin_forgot(client, "mismatch@gmail.com").cookies.get(OTP_COOKIE)
    set_otp("mismatch@gmail.com", "333333", purpose="forgot_password")
    verify_code(client, "333333", otp_token)
    reset = client.cookies.get(RESET_COOKIE)
    r = reset_password(
        client, reset_token=reset, new_password="NewPass9!", confirm="Different9!"
    )
    assert r.status_code == 422


def test_reset_password_rejects_weak_password(client):
    register_verified(client, "weak@gmail.com")
    otp_token = begin_forgot(client, "weak@gmail.com").cookies.get(OTP_COOKIE)
    set_otp("weak@gmail.com", "333333", purpose="forgot_password")
    verify_code(client, "333333", otp_token)
    reset = client.cookies.get(RESET_COOKIE)
    r = reset_password(client, reset_token=reset, new_password="weakpass")
    assert r.status_code == 422


def forged_reset_token(**overrides):
    claims = {
        "sub": "forged@gmail.com",
        "type": "otp",
        "purpose": OtpPurpose.PASSWORD_RESET.value,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
        "iss": settings.JWT_ISSUER,
    }
    claims.update(overrides)
    return jwt.encode(
        claims,
        overrides.pop("secret", settings.SECRET_KEY),
        algorithm=settings.JWT_ALGORITHM,
    )


def test_reset_password_rejects_expired_state(client):
    expired = forged_reset_token(
        exp=datetime.now(timezone.utc) - timedelta(minutes=1)
    )
    assert reset_password(client, reset_token=expired).status_code == 400


def test_reset_password_rejects_invalid_signature_state(client):
    forged = forged_reset_token(secret="attacker-secret")
    assert reset_password(client, reset_token=forged).status_code == 400


def test_reset_password_old_otp_cannot_be_reused(client):
    register_verified(client, "reuse-otp@gmail.com")
    otp_token = begin_forgot(client, "reuse-otp@gmail.com").cookies.get(OTP_COOKIE)
    set_otp("reuse-otp@gmail.com", "333333", purpose="forgot_password")
    assert verify_code(client, "333333", otp_token).status_code == 200

    # Same code + cookie again: OTP already consumed at verify.
    assert verify_code(client, "333333", otp_token).status_code == 400


# ---------------------------------------------------------------------------
# Service-level unit tests
# ---------------------------------------------------------------------------
def test_forgot_password_service_returns_none_for_unknown(clean_db):
    with SessionLocal() as db:
        svc = AuthService(db)
        assert svc.forgot_password("ghost@gmail.com") is None


def test_forgot_password_service_returns_token_for_known(clean_db):
    make_active_user("unit@gmail.com")
    with SessionLocal() as db:
        svc = AuthService(db)
        token = svc.forgot_password("unit@gmail.com")
        assert token is not None


def test_verify_forgot_otp_service_raises_on_txn_mismatch(clean_db):
    make_active_user("txnunit@gmail.com")
    with SessionLocal() as db:
        svc = AuthService(db)
        issue = svc.otp_service.issue_otp(
            "txnunit@gmail.com", OtpPurpose.FORGOT_PASSWORD
        )
        db.commit()
        set_otp("txnunit@gmail.com", "111111", purpose="forgot_password")
        bad_token = create_otp_token(
            "txnunit@gmail.com", OtpPurpose.FORGOT_PASSWORD.value, "bogus-txn"
        )
        with pytest.raises(OtpInvalidError):
            svc.verify_forgot_otp(otp_token=bad_token, otp="111111")
        assert issue.otp_id is not None


def test_reset_password_hashes_and_updates(clean_db):
    make_active_user("hashunit@gmail.com", password="OldPass1!")
    with SessionLocal() as db:
        svc = AuthService(db)
        state = svc.otp_service.create_otp_token(
            "hashunit@gmail.com", OtpPurpose.PASSWORD_RESET, None
        )
        svc.reset_password(
            reset_token=state, new_password="NewPass9!", confirm_password="NewPass9!"
        )
        db.commit()
    with SessionLocal() as db:
        creds = db.scalar(
            select(AuthCredentials).where(AuthCredentials.email == "hashunit@gmail.com")
        )
    assert creds.password_hash != "NewPass9!"
    assert verify_password("NewPass9!", creds.password_hash)
    assert not verify_password("OldPass1!", creds.password_hash)


def test_reset_password_service_requires_valid_state(clean_db):
    make_active_user("nodbstate@gmail.com")
    with SessionLocal() as db:
        svc = AuthService(db)
        with pytest.raises(OtpInvalidError):
            svc.reset_password(
                reset_token="not-a-jwt", new_password="NewPass9!", confirm_password="NewPass9!"
            )