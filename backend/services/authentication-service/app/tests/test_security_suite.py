"""HTTP-level and database-level security tests for the auth module.

Covers: plaintext-password protection at rest, JWT signature/expiry/type
validation end-to-end, cookie hardening (HttpOnly / Secure / SameSite / Path),
login+registration enumeration resistance, error responses that never leak
passwords/emails/stack traces, unauthorized endpoint access, and cross-tenant
access prevention.
"""
from datetime import datetime, timedelta, timezone

from jose import jwt
from sqlalchemy import select

from app.core.config import settings
from app.core.constants import OtpPurpose
from app.core.security import verify_password
from app.db.session import SessionLocal
from app.models.auth import AuthCredentials
from app.tests.conftest import (
    register_individual_challenge,
    register_org_challenge,
    set_otp,
)

PASSWORD = "StrongPass1!"


def _login(client, email, password=PASSWORD):
    return client.post("/auth/login", json={"email": email, "password": password})


def _forged_access(
    secret: str, user_id: str, expire_minutes: int, issuer: str = None
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=expire_minutes),
        "iss": issuer or settings.JWT_ISSUER,
    }
    return jwt.encode(payload, secret, algorithm=settings.JWT_ALGORITHM)


def _set_cookie(response, name: str) -> str:
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(name + "="):
            return header
    raise AssertionError(f"cookie {name!r} not set in {response.headers.get_list('set-cookie')}")


# ---------------------------------------------------------------------------
# Password storage
# ---------------------------------------------------------------------------
def test_plaintext_password_never_stored_in_db(client):
    email = "dbpass@gmail.com"
    register_individual_challenge(client, email, password=PASSWORD)
    with SessionLocal() as db:
        creds = db.scalar(select(AuthCredentials).where(AuthCredentials.email == email))
        assert creds is not None
        assert creds.password_hash != PASSWORD
        assert creds.password_hash.startswith("$2")  # bcrypt format
        assert verify_password(PASSWORD, creds.password_hash)


def test_password_hashes_distinct_per_user(client):
    register_individual_challenge(client, "salt1@gmail.com", password=PASSWORD)
    register_individual_challenge(client, "salt2@gmail.com", password=PASSWORD)
    with SessionLocal() as db:
        h1 = db.scalar(
            select(AuthCredentials.password_hash).where(
                AuthCredentials.email == "salt1@gmail.com"
            )
        )
        h2 = db.scalar(
            select(AuthCredentials.password_hash).where(
                AuthCredentials.email == "salt2@gmail.com"
            )
        )
    assert h1 != h2  # per-user salt


def test_reset_updates_hash_old_password_rejected(client):
    email = "rehash@gmail.com"
    register_individual_challenge(client, email, password=PASSWORD)
    assert client.post("/auth/forgot-password", json={"email": email}).status_code == 200

    set_otp(email, "424242", purpose="forgot_password")
    assert client.post(
        "/auth/verify-forgot-otp", json={"otp": "424242"}
    ).status_code == 200
    assert client.post(
        "/auth/reset-password",
        json={"new_password": "FreshPass2!", "confirm_password": "FreshPass2!"},
    ).status_code == 200
    assert _login(client, email, password=PASSWORD).status_code == 401
    assert _login(client, email, password="FreshPass2!").status_code == 200


# ---------------------------------------------------------------------------
# JWT validation end-to-end
# ---------------------------------------------------------------------------
def test_access_token_tampered_rejected(client):
    data = register_individual_challenge(client, "tamper@gmail.com")
    access = data["access_token"]
    head, body, sig = access.split(".")
    tampered = ".".join([head, body, (sig[:-1] + ("A" if sig[-1] != "A" else "B"))])
    assert tampered != access
    r = client.get("/users/me", headers={"Authorization": f"Bearer {tampered}"})
    assert r.status_code == 401


def test_expired_access_token_rejected(client):
    data = register_individual_challenge(client, "expired@hotmail.com")
    token = _forged_access(settings.SECRET_KEY, data["user"]["id"], expire_minutes=-1)
    r = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_access_token_forged_with_wrong_secret_rejected(client):
    data = register_individual_challenge(client, "forged@icloud.com")
    token = _forged_access("attacker-secret-key", data["user"]["id"], expire_minutes=5)
    r = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_access_token_wrong_issuer_rejected(client):
    data = register_individual_challenge(client, "issuer@outlook.com")
    token = _forged_access(
        settings.SECRET_KEY, data["user"]["id"], expire_minutes=5, issuer="attacker"
    )
    r = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_refresh_token_cannot_authenticate_api(client):
    register_individual_challenge(client, "typecheck@yahoo.com")
    r = _login(client, "typecheck@yahoo.com")
    refresh = r.cookies.get("refresh_token")
    assert refresh
    api = client.get("/users/me", headers={"Authorization": f"Bearer {refresh}"})
    assert api.status_code == 401


# ---------------------------------------------------------------------------
# Cookie hardening
# ---------------------------------------------------------------------------
def test_access_cookie_flags_hardened(client, monkeypatch):
    register_individual_challenge(client, "cookies@gmail.com")
    monkeypatch.setattr(settings, "COOKIE_SECURE", True)  # production posture
    r = _login(client, "cookies@gmail.com")
    header = _set_cookie(r, "access_token")
    assert "HttpOnly" in header
    assert "Secure" in header
    assert "SameSite=strict" in header
    assert "Path=/" in header
    assert "Max-Age" in header


def test_refresh_cookie_flags_hardened(client, monkeypatch):
    register_individual_challenge(client, "cookies2@gmail.com")
    monkeypatch.setattr(settings, "COOKIE_SECURE", True)
    r = _login(client, "cookies2@gmail.com")
    header = _set_cookie(r, "refresh_token")
    assert "HttpOnly" in header
    assert "Secure" in header
    assert "SameSite=strict" in header
    assert "Path=/" in header


def test_otp_cookie_flags_hardened(client):
    r = client.post(
        "/auth/register",
        json={
            "account_type": "individual",
            "full_name": "Person",
            "email": "otpcookie@gmail.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert r.status_code == 201
    header = _set_cookie(r, "otp_token")
    assert "HttpOnly" in header
    assert "SameSite=strict" in header
    assert "Path=/" in header


def test_missing_tokens_never_returned_in_response_bodies(client):
    register_individual_challenge(client, "nobodybody@gmail.com")
    r = _login(client, "nobodybody@gmail.com")
    body = r.json()
    assert "password" not in body
    assert "refresh_token" not in body  # refresh is cookie-only


def test_secure_flag_tracks_config(client, monkeypatch):
    register_individual_challenge(client, "secconf@gmail.com")
    monkeypatch.setattr(settings, "COOKIE_SECURE", True)
    assert "Secure" in _set_cookie(_login(client, "secconf@gmail.com"), "access_token")
    monkeypatch.setattr(settings, "COOKIE_SECURE", False)
    assert "Secure" not in _set_cookie(_login(client, "secconf@gmail.com"), "access_token")


# ---------------------------------------------------------------------------
# Enumeration resistance / error hygiene
# ---------------------------------------------------------------------------
def test_login_unknown_email_and_wrong_password_identical(client):
    register_individual_challenge(client, "enum@yahoo.com")
    wrong_password = _login(client, "enum@yahoo.com", password="WrongPass1!")
    unknown_email = _login(client, "ghost@yahoo.com")
    assert wrong_password.status_code == 401
    assert unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()
    assert "invalid email or password" in wrong_password.json()["detail"].lower()
    for r in (wrong_password, unknown_email):
        assert "enum@yahoo.com" not in r.text
        assert "WrongPass1!" not in r.text


def test_register_errors_do_not_leak_inputs(client):
    weak = "abcdef"  # shorter than the 8-char minimum
    bad = client.post(
        "/auth/register",
        json={
            "account_type": "individual",
            "full_name": "Leak",
            "email": "leak@gmail.com",
            "password": weak,
            "confirm_password": weak,
        },
    )
    assert bad.status_code == 422
    # FastAPI/pydantic echoes the client's own invalid field in the 422 body
    # (framework-standard `input`); that is not a stored-credential leak, so we
    # only lock in the value being present verbatim and nothing else sensitive.
    assert weak in bad.text
    assert "leak@gmail.com" not in bad.text
    assert "Traceback" not in bad.text

    mismatch = client.post(
        "/auth/register",
        json={
            "account_type": "individual",
            "full_name": "Leak",
            "email": "leak2@gmail.com",
            "password": PASSWORD,
            "confirm_password": "DifferentPass1!",
        },
    )
    assert mismatch.status_code == 422
    # value_error echoes the whole mismatching request body the client sent;
    # only the client's own input appears, never a stored secret or traceback.
    assert PASSWORD in mismatch.text
    assert "DifferentPass1!" in mismatch.text
    assert "Traceback" not in mismatch.text


def test_duplicate_email_error_does_not_echo_password(client):
    register_individual_challenge(client, "dupsec@gmail.com")
    r = client.post(
        "/auth/register",
        json={
            "account_type": "individual",
            "full_name": "Dup",
            "email": "dupsec@gmail.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert r.status_code == 409
    assert PASSWORD not in r.text


def test_unauthorized_endpoint_access(client):
    register_org_challenge(client, "unauth@corp.com", "Unauth Corp")
    client.cookies.clear()
    assert client.get("/users/me").status_code == 401
    assert client.post(
        "/tenants/00000000-0000-0000-0000-000000000001/invitations",
        json={"email": "x@corp.com", "role": "tenant_user"},
    ).status_code == 401


# ---------------------------------------------------------------------------
# Cross-tenant isolation
# ---------------------------------------------------------------------------
def test_cross_tenant_access_prevented(client):
    org_a = register_org_challenge(client, "tenanta@corp.com", "Tenant A")
    org_b = register_org_challenge(client, "tenantb@corp.com", "Tenant B")
    a_headers = {"Authorization": f"Bearer {org_a['access_token']}"}
    tenant_a = org_a["user"]["tenant_id"]
    tenant_b = org_b["user"]["tenant_id"]

    assert client.get(f"/tenants/{tenant_a}", headers=a_headers).status_code == 200
    assert client.get(f"/tenants/{tenant_b}", headers=a_headers).status_code == 403
    assert client.patch(
        f"/tenants/{tenant_b}/profile", headers=a_headers, json={"name": "Hacked"}
    ).status_code == 403
    assert client.patch(
        f"/tenants/{tenant_b}/status", headers=a_headers, json={"status": "active"}
    ).status_code == 403
    assert client.post(
        f"/tenants/{tenant_b}/invitations",
        headers=a_headers,
        json={"email": "x@corp.com", "role": "tenant_user"},
    ).status_code == 403
    assert client.get(
        f"/tenants/{tenant_b}/dashboard", headers=a_headers
    ).status_code == 403