"""POST /auth/refresh-token tests.

Covers the full refresh flow: cookie read, JWT signature/type/expiry/jti
validation, stored refresh-token state, rotation (previous token revoked, new
token issued), reuse rejection, and cookie replacement. Refresh tokens are
never returned in the JSON body.
"""
from datetime import datetime, timedelta, timezone

from jose import jwt
from sqlalchemy import select

from app.core.config import settings
from app.core.constants import TokenType
from app.core.security import decode_token, hash_jti
from app.db.session import SessionLocal
from app.models.auth import AuthRefreshToken
from app.tests.conftest import set_otp

REFRESH_COOKIE = settings.REFRESH_TOKEN_COOKIE_NAME
ACCESS_COOKIE = settings.ACCESS_TOKEN_COOKIE_NAME


def register_verified(client, email, otp="111111"):
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
    token = r.cookies["otp_token"]
    set_otp(email, otp, purpose="registration")
    resp = client.post(
        "/auth/verify-otp",
        json={"otp": otp},
        cookies={"otp_token": token},
    )
    assert resp.status_code == 200


def login(client, email):
    r = client.post("/auth/login", json={"email": email, "password": "StrongPass1!"})
    assert r.status_code == 200
    return r.json(), client.cookies.get(REFRESH_COOKIE)


def forged_refresh_token(**overrides):
    claims = {
        "sub": "user-123",
        "type": "refresh",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "iss": settings.JWT_ISSUER,
        "jti": "forged-jti",
    }
    claims.update(overrides)
    return jwt.encode(
        claims, overrides.pop("secret", settings.SECRET_KEY), algorithm=settings.JWT_ALGORITHM
    )


def stored_record(token_hash):
    with SessionLocal() as db:
        return db.scalar(
            select(AuthRefreshToken).where(AuthRefreshToken.token_hash == token_hash)
        )


def test_refresh_valid(client):
    register_verified(client, "valid@gmail.com")
    _, old_refresh = login(client, "valid@gmail.com")

    r = client.post("/auth/refresh-token")
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"]
    assert body["user"]["email"] == "valid@gmail.com"
    assert "refresh_token" not in body

    new_refresh = client.cookies.get(REFRESH_COOKIE)
    assert new_refresh and new_refresh != old_refresh
    assert client.cookies.get(ACCESS_COOKIE)


def test_refresh_missing_cookie(client):
    r = client.post("/auth/refresh-token")
    assert r.status_code == 401


def test_refresh_expired_token(client):
    expired = forged_refresh_token(
        exp=datetime.now(timezone.utc) - timedelta(days=1),
        iat=datetime.now(timezone.utc) - timedelta(days=30),
    )
    r = client.post("/auth/refresh-token", cookies={REFRESH_COOKIE: expired})
    assert r.status_code == 401


def test_refresh_invalid_signature(client):
    forged = forged_refresh_token(secret="attacker-secret")
    r = client.post("/auth/refresh-token", cookies={REFRESH_COOKIE: forged})
    assert r.status_code == 401


def test_refresh_wrong_token_type(client):
    register_verified(client, "accesstoken@gmail.com")
    data, _ = login(client, "accesstoken@gmail.com")
    r = client.post(
        "/auth/refresh-token",
        cookies={REFRESH_COOKIE: data["access_token"]},
    )
    assert r.status_code == 401


def test_refresh_revoked_token(client):
    register_verified(client, "revoked@gmail.com")
    old_refresh = login(client, "revoked@gmail.com")[1]
    assert client.post("/auth/logout").status_code == 200

    r = client.post("/auth/refresh-token", cookies={REFRESH_COOKIE: old_refresh})
    assert r.status_code == 401


def test_refresh_reused_token(client):
    register_verified(client, "reuse@gmail.com")
    old_refresh = login(client, "reuse@gmail.com")[1]

    assert client.post("/auth/refresh-token").status_code == 200

    r = client.post("/auth/refresh-token", cookies={REFRESH_COOKIE: old_refresh})
    assert r.status_code == 401


def test_refresh_rotates_stored_token(client):
    register_verified(client, "rotate@gmail.com")
    old_refresh = login(client, "rotate@gmail.com")[1]
    old_jti = decode_token(old_refresh, TokenType.REFRESH)["jti"]

    assert client.post("/auth/refresh-token").status_code == 200

    new_jti = decode_token(client.cookies.get(REFRESH_COOKIE), TokenType.REFRESH)["jti"]
    old_record = stored_record(hash_jti(old_jti))
    new_record = stored_record(hash_jti(new_jti))

    assert old_record.is_revoked is True
    assert old_record.revoked_at is not None
    assert new_record is not None
    assert new_record.is_revoked is False
    assert new_record.rotated_from == old_record.id


def test_refresh_returns_new_access_token(client):
    register_verified(client, "newtokens@gmail.com")
    data, old_refresh = login(client, "newtokens@gmail.com")

    r = client.post("/auth/refresh-token")
    assert r.status_code == 200
    new_access = decode_token(r.json()["access_token"], TokenType.ACCESS)
    new_refresh = client.cookies.get(REFRESH_COOKIE)

    # Same-second JWTs produce identical strings; assert a valid freshly issued
    # access token for the same subject instead of string inequality.
    assert new_access["type"] == "access"
    assert new_access["sub"] == data["user"]["id"]
    assert new_access["role"] == "individual"
    assert new_refresh and new_refresh != old_refresh