from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt

from app.core.config import settings
from app.core.constants import TokenType
from app.core.exceptions import ValidationError_
from app.core.security import (
    create_access_token,
    create_otp_token,
    create_refresh_token,
    decode_token,
    extract_user_id,
    generate_otp,
    get_cookie_params,
    hash_jti,
    hash_otp,
    hash_password,
    validate_password,
    verify_password,
)


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
def test_hash_password_not_plaintext():
    h = hash_password("StrongPass1!")
    assert h != "StrongPass1!"
    assert h.startswith("$2")
    assert verify_password("StrongPass1!", h)


def test_verify_password_wrong():
    h = hash_password("StrongPass1!")
    assert verify_password("WrongPass1!", h) is False


def test_password_hashes_are_salted():
    assert hash_password("StrongPass1!") != hash_password("StrongPass1!")


# ---------------------------------------------------------------------------
# Password policy
# ---------------------------------------------------------------------------
def test_password_policy_valid():
    assert validate_password("StrongPass1!") == "StrongPass1!"


def test_password_policy_too_short():
    with pytest.raises(ValidationError_):
        validate_password("Ab1!")


def test_password_policy_too_long():
    with pytest.raises(ValidationError_):
        validate_password("A" * (settings.PASSWORD_MAX_LENGTH + 1) + "b1!")


def test_password_policy_missing_uppercase():
    with pytest.raises(ValidationError_):
        validate_password("strongpass1!")


def test_password_policy_missing_lowercase():
    with pytest.raises(ValidationError_):
        validate_password("STRONGPASS1!")


def test_password_policy_missing_number():
    with pytest.raises(ValidationError_):
        validate_password("StrongPass!")


def test_password_policy_missing_special():
    with pytest.raises(ValidationError_):
        validate_password("StrongPass1")


# ---------------------------------------------------------------------------
# Token creation / decoding
# ---------------------------------------------------------------------------
def test_access_token_roundtrip():
    token = create_access_token("user-123", "individual", "tenant-1")
    payload = decode_token(token, TokenType.ACCESS)
    assert extract_user_id(payload) == "user-123"
    assert payload["type"] == "access"
    assert payload["role"] == "individual"
    assert payload["tenant_id"] == "tenant-1"
    assert payload["iss"] == settings.JWT_ISSUER


def test_access_token_optional_tenant():
    token = create_access_token("user-123", "individual")
    payload = decode_token(token)
    assert "tenant_id" not in payload


def test_access_token_claims_are_minimal():
    payload = decode_token(
        create_access_token("user-123", "individual", "tenant-1"), TokenType.ACCESS
    )
    assert set(payload).issubset(
        {"sub", "type", "iat", "exp", "iss", "role", "tenant_id"}
    )
    assert payload["role"] == "individual"
    assert payload["tenant_id"] == "tenant-1"


def test_refresh_token_claims_are_minimal():
    token, jti = create_refresh_token("user-123")
    payload = decode_token(token, TokenType.REFRESH)
    assert set(payload).issubset({"sub", "type", "iat", "exp", "iss", "jti"})
    assert payload["jti"] == jti


def test_token_expiry_config_in_bounds():
    assert 15 <= settings.ACCESS_TOKEN_EXPIRE_MINUTES <= 30
    assert 7 <= settings.REFRESH_TOKEN_EXPIRE_DAYS <= 30


def test_refresh_token_roundtrip():
    token, jti = create_refresh_token("user-123")
    payload = decode_token(token, TokenType.REFRESH)
    assert payload["type"] == "refresh"
    assert payload["jti"] == jti
    assert extract_user_id(payload) == "user-123"


def test_otp_token_roundtrip():
    token = create_otp_token("user-123", "email_verify")
    payload = decode_token(token, TokenType.OTP)
    assert payload["type"] == "otp"
    assert payload["purpose"] == "email_verify"
    assert extract_user_id(payload) == "user-123"


def test_decode_rejects_wrong_purpose():
    access = create_access_token("u1", "individual")
    with pytest.raises(ValueError):
        decode_token(access, TokenType.REFRESH)


def test_decode_rejects_invalid_token():
    with pytest.raises(ValueError):
        decode_token("not-a-jwt", None)


def test_decode_rejects_expired_token():
    now = datetime.now(timezone.utc)
    expired = jwt.encode(
        {
            "sub": "u1",
            "type": "access",
            "iat": now - timedelta(minutes=10),
            "exp": now - timedelta(minutes=1),
            "iss": settings.JWT_ISSUER,
        },
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(ValueError):
        decode_token(expired, TokenType.ACCESS)


def test_decode_rejects_wrong_issuer():
    now = datetime.now(timezone.utc)
    forged = jwt.encode(
        {
            "sub": "u1",
            "type": "access",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "iss": "attacker",
        },
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(ValueError):
        decode_token(forged, TokenType.ACCESS)


def test_extract_user_id_missing():
    assert extract_user_id({}) is None


# ---------------------------------------------------------------------------
# Refresh token security
# ---------------------------------------------------------------------------
def test_jti_hash_consistent():
    assert hash_jti("abc123") == hash_jti("abc123")
    assert len(hash_jti("abc123")) == 64
    assert hash_jti("abc123") != hash_jti("abc124")


def test_refresh_token_stores_hash_not_plaintext():
    token, jti = create_refresh_token("u1")
    assert hash_jti(jti) != jti
    assert token not in (jti, hash_jti(jti))


# ---------------------------------------------------------------------------
# OTP
# ---------------------------------------------------------------------------
def test_generate_otp_digits():
    otp = generate_otp()
    assert otp.isdigit()
    assert len(otp) == settings.OTP_LENGTH


def test_generate_otp_custom_length():
    assert len(generate_otp(8)) == 8


def test_hash_otp_not_plaintext():
    h = hash_otp("123456")
    assert h != "123456"


# ---------------------------------------------------------------------------
# Cookie configuration
# ---------------------------------------------------------------------------
def test_cookie_params_defaults():
    params = get_cookie_params()
    assert params["httponly"] is True
    assert params["secure"] == settings.COOKIE_SECURE
    assert params["samesite"] == settings.COOKIE_SAMESITE
    assert params["path"] == settings.COOKIE_PATH
    assert "domain" not in params
