import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings
from app.core.constants import TokenType
from app.core.exceptions import ValidationError_


def utcnow() -> datetime:
    """Return current UTC time as a naive datetime.

    SQLAlchemy DateTime columns are timezone-naive (SQLite and MySQL), so the
    application consistently stores and compares naive UTC datetimes.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"), password_hash.encode("utf-8")
        )
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Password policy
# ---------------------------------------------------------------------------
def validate_password(password: str) -> str:
    """Enforce the configurable password policy.

    Raises ValidationError_ if the password violates any configured rule.
    Returns the password unchanged on success.
    """
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        raise ValidationError_(
            f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters"
        )
    if len(password) > settings.PASSWORD_MAX_LENGTH:
        raise ValidationError_(
            f"Password must be at most {settings.PASSWORD_MAX_LENGTH} characters"
        )
    if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
        raise ValidationError_("Password must contain an uppercase letter")
    if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
        raise ValidationError_("Password must contain a lowercase letter")
    if settings.PASSWORD_REQUIRE_NUMBER and not re.search(r"\d", password):
        raise ValidationError_("Password must contain a number")
    if settings.PASSWORD_REQUIRE_SPECIAL and not re.search(
        r"[^A-Za-z0-9]", password
    ):
        raise ValidationError_("Password must contain a special character")
    return password


# ---------------------------------------------------------------------------
# Token creation / decoding
# ---------------------------------------------------------------------------
def _create_token(subject: str, token_type: TokenType, expires_delta: timedelta,
                  extra: Optional[dict] = None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type.value,
        "iat": now,
        "exp": now + expires_delta,
        "iss": settings.JWT_ISSUER,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_access_token(user_id: str, role: str, tenant_id: Optional[str] = None) -> str:
    extra = {"role": role}
    if tenant_id:
        extra["tenant_id"] = tenant_id
    return _create_token(
        user_id,
        TokenType.ACCESS,
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        extra,
    )


def create_refresh_token(user_id: str) -> tuple[str, str]:
    jti = secrets.token_hex(16)
    token = _create_token(
        user_id,
        TokenType.REFRESH,
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        {"jti": jti},
    )
    return token, jti


def create_otp_token(
    user_id: str, purpose: str, txn: Optional[str] = None
) -> str:
    extra = {"purpose": purpose}
    if txn:
        extra["txn"] = txn
    return _create_token(
        user_id,
        TokenType.OTP,
        timedelta(minutes=settings.OTP_TOKEN_EXPIRE_MINUTES),
        extra,
    )


def validate_otp_token(token: str, expected_purpose: Optional[str] = None) -> dict:
    """Decode and validate an OTP JWT.

    Verifies signature, expiry, issuer, token type (otp), and (when provided)
    the purpose. Returns the payload on success; raises ValueError otherwise.
    """
    payload = decode_token(token, TokenType.OTP)
    if expected_purpose and payload.get("purpose") != expected_purpose:
        raise ValueError("Unexpected OTP purpose")
    return payload


def decode_token(token: str, expected_type: Optional[TokenType] = None) -> dict:
    """Decode and validate a JWT.

    - Verifies signature, exp (expiry) and iss (issuer).
    - When expected_type is provided, verifies the token purpose/type.
    Raises ValueError on invalid, expired, or wrong-type tokens.
    """
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except JWTError:
        raise ValueError("Invalid or expired token")
    if payload.get("iss") != settings.JWT_ISSUER:
        raise ValueError("Invalid token issuer")
    if expected_type and payload.get("type") != expected_type.value:
        raise ValueError("Unexpected token type")
    return payload


def extract_user_id(payload: dict) -> Optional[str]:
    """Return the subject (user id) from a decoded token payload."""
    sub = payload.get("sub")
    return sub if isinstance(sub, str) and sub else None


# ---------------------------------------------------------------------------
# Refresh token security
# ---------------------------------------------------------------------------
def hash_jti(jti: str) -> str:
    """SHA-256 hash of a refresh token jti; only this is stored in the DB."""
    return hashlib.sha256(jti.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# OTP
# ---------------------------------------------------------------------------
def generate_otp(length: int = None) -> str:
    length = length or settings.OTP_LENGTH
    return f"{secrets.randbelow(10 ** length):0{length}d}"


def hash_otp(otp: str) -> str:
    """Hash an OTP code before storage (bcrypt)."""
    return hash_password(otp)


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------
def get_cookie_params() -> dict:
    """Return the common authentication cookie parameters."""
    return {
        "httponly": settings.COOKIE_HTTPONLY,
        "secure": settings.COOKIE_SECURE,
        "samesite": settings.COOKIE_SAMESITE,
        "path": settings.COOKIE_PATH,
    }


def get_cookie_params_with_domain() -> dict:
    params = get_cookie_params()
    if settings.COOKIE_DOMAIN:
        params["domain"] = settings.COOKIE_DOMAIN
    return params


def get_otp_token_cookie_params() -> dict:
    """Return cookie params for the short-lived OTP token cookie."""
    params = get_cookie_params_with_domain()
    params["max_age"] = settings.OTP_TOKEN_EXPIRE_MINUTES * 60
    return params


def get_otp_token_cookie_clear_params() -> dict:
    """Return cookie params used to clear the OTP token cookie."""
    params = {"httponly": settings.COOKIE_HTTPONLY, "path": settings.COOKIE_PATH}
    if settings.COOKIE_DOMAIN:
        params["domain"] = settings.COOKIE_DOMAIN
    return params
