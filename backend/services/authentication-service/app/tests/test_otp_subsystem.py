import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.core.constants import OtpPurpose, TokenType
from app.core.exceptions import OtpInvalidError, OtpMaxAttemptsError, OtpResendTooSoonError, ValidationError_
from app.core.security import (
    create_otp_token,
    get_otp_token_cookie_params,
    hash_otp,
    validate_otp_token,
    verify_password,
)
from app.db.session import SessionLocal
from app.models.auth import AuthOtp
from app.services.otp_service import OtpService

naive_utc = lambda: datetime.now(timezone.utc).replace(tzinfo=None)  # noqa: E731


def _active_otp(email, purpose):
    with SessionLocal() as db:
        return db.scalar(
            select(AuthOtp)
            .where(AuthOtp.email == email, AuthOtp.purpose == purpose)
            .order_by(AuthOtp.created_at.desc())
        )


def _seed_otp(email, purpose, expires_delta=timedelta(minutes=5), code="123456", max_attempts=3):
    with SessionLocal() as db:
        otp = AuthOtp(
            email=email,
            purpose=purpose,
            otp_hash=hash_otp(code),
            expires_at=naive_utc() + expires_delta,
            max_attempts=max_attempts,
        )
        db.add(otp)
        db.commit()
        return otp.id


# ---------------------------------------------------------------------------
# OTP generator
# ---------------------------------------------------------------------------
def test_generate_otp_length_default(client):
    with SessionLocal() as db:
        issue = OtpService(db).issue_otp("gen@example.com", OtpPurpose.REGISTRATION)
    assert issue.code.isdigit()
    assert len(issue.code) == settings.OTP_LENGTH


def test_generate_otp_custom_length(client, monkeypatch):
    monkeypatch.setattr(settings, "OTP_LENGTH", 8)
    with SessionLocal() as db:
        issue = OtpService(db).issue_otp("gen8@example.com", OtpPurpose.REGISTRATION)
    assert len(issue.code) == 8


# ---------------------------------------------------------------------------
# OTP storage (only hashed, never plaintext)
# ---------------------------------------------------------------------------
def test_otp_stored_hashed_not_plaintext(client):
    email = "hash@example.com"
    with SessionLocal() as db:
        issue = OtpService(db).issue_otp(email, OtpPurpose.REGISTRATION)
        row = db.get(AuthOtp, issue.otp_id)
    assert row.otp_hash != issue.code
    assert verify_password(issue.code, row.otp_hash)


# ---------------------------------------------------------------------------
# Verification success invalidates OTP
# ---------------------------------------------------------------------------
def test_otp_verify_success_invalidates(client):
    email = "ok@example.com"
    with SessionLocal() as db:
        svc = OtpService(db)
        issue = svc.issue_otp(email, OtpPurpose.REGISTRATION)
        otp_id = svc.verify_otp(email, issue.code, OtpPurpose.REGISTRATION)
        db.commit()
    assert otp_id == issue.otp_id
    row = _active_otp(email, OtpPurpose.REGISTRATION.value)
    assert row.revoked_at is not None


# ---------------------------------------------------------------------------
# Expired OTP rejected
# ---------------------------------------------------------------------------
def test_otp_expired_rejected(client):
    email = "exp@example.com"
    otp_id = _seed_otp(email, OtpPurpose.REGISTRATION.value, expires_delta=timedelta(minutes=-1))
    with SessionLocal() as db:
        with pytest.raises(OtpInvalidError):
            OtpService(db).verify_otp(email, "123456", OtpPurpose.REGISTRATION)


# ---------------------------------------------------------------------------
# Incorrect OTP increments retry count
# ---------------------------------------------------------------------------
def test_otp_wrong_increments_attempts(client):
    email = "attempt@example.com"
    with SessionLocal() as db:
        svc = OtpService(db)
        issue = svc.issue_otp(email, OtpPurpose.REGISTRATION)
        with pytest.raises(OtpInvalidError):
            svc.verify_otp(email, "000000", OtpPurpose.REGISTRATION)
        db.commit()
    row = _active_otp(email, OtpPurpose.REGISTRATION.value)
    assert row.attempt_count == 1
    assert row.revoked_at is None


# ---------------------------------------------------------------------------
# Max attempts exceeded invalidates OTP
# ---------------------------------------------------------------------------
def test_otp_max_attempts_invalidates(client):
    email = "max@example.com"
    with SessionLocal() as db:
        svc = OtpService(db)
        issue = svc.issue_otp(email, OtpPurpose.REGISTRATION)
        for _ in range(3):
            with pytest.raises((OtpInvalidError, OtpMaxAttemptsError)):
                svc.verify_otp(email, "000000", OtpPurpose.REGISTRATION)
            db.commit()
        # correct code must now fail because OTP was revoked at limit
        with pytest.raises(OtpInvalidError):
            svc.verify_otp(email, issue.code, OtpPurpose.REGISTRATION)
    row = _active_otp(email, OtpPurpose.REGISTRATION.value)
    assert row.revoked_at is not None


def test_otp_max_attempts_configurable(client, monkeypatch):
    monkeypatch.setattr(settings, "OTP_MAX_ATTEMPTS", 2)
    email = "max2@example.com"
    with SessionLocal() as db:
        svc = OtpService(db)
        issue = svc.issue_otp(email, OtpPurpose.REGISTRATION)
        for _ in range(2):
            with pytest.raises((OtpInvalidError, OtpMaxAttemptsError)):
                svc.verify_otp(email, "000000", OtpPurpose.REGISTRATION)
            db.commit()
        with pytest.raises(OtpInvalidError):
            svc.verify_otp(email, issue.code, OtpPurpose.REGISTRATION)


# ---------------------------------------------------------------------------
# Resend invalidates previous active OTP
# ---------------------------------------------------------------------------
def test_resend_revokes_previous(client):
    email = "resend@example.com"
    with SessionLocal() as db:
        svc = OtpService(db)
        first = svc.issue_otp(email, OtpPurpose.REGISTRATION)
        second = svc.issue_otp(email, OtpPurpose.REGISTRATION)
        db.commit()
    first_row = db_get(AuthOtp, first.otp_id)
    second_row = db_get(AuthOtp, second.otp_id)
    assert first_row.revoked_at is not None
    assert second_row.revoked_at is None
    # old code must no longer validate
    with SessionLocal() as db:
        with pytest.raises(OtpInvalidError):
            OtpService(db).verify_otp(email, first.code, OtpPurpose.REGISTRATION)


def db_get(model, pk):
    with SessionLocal() as db:
        return db.get(model, pk)


# ---------------------------------------------------------------------------
# Resend cooldown / abuse protection
# ---------------------------------------------------------------------------
def test_resend_cooldown_blocks(client):
    email = "cooldown@example.com"
    with SessionLocal() as db:
        svc = OtpService(db)
        svc.resend_otp(email, OtpPurpose.REGISTRATION)
        with pytest.raises(OtpResendTooSoonError):
            svc.resend_otp(email, OtpPurpose.REGISTRATION)


def test_resend_cooldown_allowed_after_interval(client, monkeypatch):
    monkeypatch.setattr(settings, "OTP_RESEND_COOLDOWN_SECONDS", 0)
    email = "coolok@example.com"
    with SessionLocal() as db:
        svc = OtpService(db)
        svc.resend_otp(email, OtpPurpose.REGISTRATION)
        issue = svc.resend_otp(email, OtpPurpose.REGISTRATION)
    assert issue.code.isdigit()


# ---------------------------------------------------------------------------
# OTP JWT
# ---------------------------------------------------------------------------
def test_otp_token_roundtrip(client):
    token = create_otp_token(email := "user@gmail.com", "registration", txn="txn-123")
    payload = validate_otp_token(token, expected_purpose="registration")
    assert payload["type"] == "otp"
    assert payload["purpose"] == "registration"
    assert payload["txn"] == "txn-123"
    assert payload["sub"] == email


def test_otp_token_wrong_purpose(client):
    token = create_otp_token("user@gmail.com", "registration", txn="txn-1")
    with pytest.raises(ValueError):
        validate_otp_token(token, expected_purpose="forgot_password")


def test_otp_token_expired(client):
    import jwt as pyjwt

    now = datetime.now(timezone.utc)
    expired = pyjwt.encode(
        {
            "sub": "user@gmail.com",
            "type": "otp",
            "purpose": "registration",
            "iat": now - timedelta(minutes=10),
            "exp": now - timedelta(minutes=5),
            "iss": settings.JWT_ISSUER,
        },
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(ValueError):
        validate_otp_token(expired, expected_purpose="registration")


def test_otp_service_create_and_validate_token(client):
    email = "svc@example.com"
    with SessionLocal() as db:
        svc = OtpService(db)
        issue = svc.issue_otp(email, OtpPurpose.REGISTRATION)
        token = svc.create_otp_token(email, OtpPurpose.REGISTRATION, issue.otp_id)
        payload = svc.validate_otp_token(token, OtpPurpose.REGISTRATION)
    assert payload["txn"] == issue.otp_id
    assert payload["purpose"] == OtpPurpose.REGISTRATION.value


# ---------------------------------------------------------------------------
# OTP cookie management
# ---------------------------------------------------------------------------
def test_otp_token_cookie_params(client):
    params = get_otp_token_cookie_params()
    assert params["httponly"] is True
    assert params["samesite"] == settings.COOKIE_SAMESITE
    assert params["path"] == settings.COOKIE_PATH
    assert params["max_age"] == settings.OTP_TOKEN_EXPIRE_MINUTES * 60
