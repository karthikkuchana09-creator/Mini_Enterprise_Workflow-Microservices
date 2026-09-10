"""POST /auth/logout tests.

Covers server-side invalidation of the refresh token, clearing of both the
access and refresh cookies using the same path/domain/security config used to
set them, idempotent/safe behavior, and the inability to renew a session after
logout.
"""
from sqlalchemy import select

from app.core.config import settings
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
    return r.json()


def clear_cookie_headers(response):
    return [
        v.lower()
        for k, v in response.headers.multi_items()
        if k.lower() == "set-cookie"
    ]


def test_logout_clears_access_and_refresh_cookies(client):
    register_verified(client, "cleared@gmail.com")
    login(client, "cleared@gmail.com")
    assert client.cookies.get(ACCESS_COOKIE)
    assert client.cookies.get(REFRESH_COOKIE)

    r = client.post("/auth/logout")
    assert r.status_code == 200
    assert r.json()["message"] == "Logged out."
    assert "access_token" not in r.json()

    assert client.cookies.get(ACCESS_COOKIE) is None
    assert client.cookies.get(REFRESH_COOKIE) is None


def test_logout_revokes_refresh_token(client):
    register_verified(client, "revoked@gmail.com")
    login(client, "revoked@gmail.com")

    client.post("/auth/logout")
    with SessionLocal() as db:
        tokens = db.scalars(select(AuthRefreshToken)).all()
    assert tokens
    assert all(t.is_revoked for t in tokens)


def test_logout_subsequent_refresh_fails(client):
    register_verified(client, "subsequent@gmail.com")
    login(client, "subsequent@gmail.com")
    old_refresh = client.cookies.get(REFRESH_COOKIE)

    assert client.post("/auth/logout").status_code == 200

    r = client.post("/auth/refresh-token", cookies={REFRESH_COOKIE: old_refresh})
    assert r.status_code == 401


def test_logout_session_cannot_be_renewed(client):
    register_verified(client, "renew@gmail.com")
    login(client, "renew@gmail.com")
    old_refresh = client.cookies.get(REFRESH_COOKIE)

    assert client.post("/auth/logout").status_code == 200
    assert client.cookies.get(ACCESS_COOKIE) is None

    renew = client.post("/auth/refresh-token", cookies={REFRESH_COOKIE: old_refresh})
    assert renew.status_code == 401


def test_logout_clears_cookies_with_matching_config(client):
    register_verified(client, "config@gmail.com")
    login(client, "config@gmail.com")

    headers = clear_cookie_headers(client.post("/auth/logout"))
    access_clear = next(
        (h for h in headers if h.startswith(f"{ACCESS_COOKIE}=")), None
    )
    refresh_clear = next(
        (h for h in headers if h.startswith(f"{REFRESH_COOKIE}=")), None
    )
    assert access_clear is not None
    assert refresh_clear is not None
    assert "httponly" in access_clear
    assert "httponly" in refresh_clear
    assert f"path={settings.COOKIE_PATH.lower()}" in access_clear
    assert f"path={settings.COOKIE_PATH.lower()}" in refresh_clear


def test_logout_idempotent_without_cookie(client):
    r = client.post("/auth/logout")
    assert r.status_code == 200
    assert r.json()["message"] == "Logged out."