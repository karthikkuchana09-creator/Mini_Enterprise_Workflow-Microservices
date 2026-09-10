"""POST /auth/login tests.

Covers the login flow for every supported user type (individual, tenant admin,
tenant user), the HttpOnly access/refresh cookie setup, error handling, and the
minimal JWT claim contract (no passwords, OTPs, or sensitive profile data).
"""
from app.core.constants import TokenType, UserRole, UserStatus, UserType
from app.core.security import decode_token, hash_password
from app.db.session import SessionLocal
from app.repositories.auth_repo import AuthRepository
from app.services.user_service import UserService
from app.tests.conftest import set_otp
from tenant.services.tenant_service import TenantService


def register_verified_individual(client, email, otp="111111"):
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


def register_verified_admin(client, email, org_name="Login Corp", otp="222222"):
    r = client.post(
        "/auth/register",
        json={
            "full_name": "Boss",
            "email": email,
            "organization_name": org_name,
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
            "account_type": "organization",
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


def create_tenant_user(email):
    with SessionLocal() as db:
        tenant_service = TenantService(db)
        tenant_service.create_tenant(name="Login User Corp", org_email=email)
        tenant = tenant_service.get_tenant_by_org_email(email)
        user = UserService(db).create_user(
            email=email,
            full_name="Member",
            user_type=UserType.TENANT_USER,
            role=UserRole.TENANT_USER,
            status=UserStatus.ACTIVE,
            tenant_id=tenant.id,
        )
        AuthRepository(db).create_credentials(
            user_id=user.id,
            email=email,
            password_hash=hash_password("StrongPass1!"),
            is_active=True,
        )
        AuthRepository(db).mark_email_verified(user.id)
        db.commit()
        return user.id, tenant.id


def login(client, email, password="StrongPass1!"):
    return client.post("/auth/login", json={"email": email, "password": password})


def set_cookie_headers(response):
    return [v for k, v in response.headers.multi_items() if k.lower() == "set-cookie"]


def test_login_individual_success(client):
    register_verified_individual(client, "single@gmail.com")
    r = login(client, "single@gmail.com")
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"]
    assert body["user"]["role"] == "individual"
    assert body["user"]["tenant_id"] is None


def test_login_sets_httponly_access_and_refresh_cookies(client):
    register_verified_individual(client, "cookies@gmail.com")
    r = login(client, "cookies@gmail.com")

    sorted_headers = [h.lower() for h in set_cookie_headers(r)]
    access_header = next(filter(lambda h: h.startswith("access_token="), sorted_headers), None)
    refresh_header = next(filter(lambda h: h.startswith("refresh_token="), sorted_headers), None)
    assert access_header is not None
    assert refresh_header is not None
    assert "httponly" in access_header
    assert "httponly" in refresh_header
    assert "path=" in access_header

    assert r.cookies.get("access_token") == r.json()["access_token"]
    assert r.cookies.get("refresh_token") is not None


def test_login_tenant_admin_success(client):
    register_verified_admin(client, "boss@logincorp.io")
    r = login(client, "boss@logincorp.io")
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["role"] == "tenant_admin"
    assert body["user"]["tenant_id"] is not None

    payload = decode_token(body["access_token"], TokenType.ACCESS)
    assert payload["role"] == "tenant_admin"
    assert payload["tenant_id"] == body["user"]["tenant_id"]


def test_login_tenant_user_success(client):
    user_id, tenant_id = create_tenant_user("member@logincorp.io")
    r = login(client, "member@logincorp.io")
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["role"] == "tenant_user"
    assert body["user"]["tenant_id"] == tenant_id

    payload = decode_token(body["access_token"], TokenType.ACCESS)
    assert payload["role"] == "tenant_user"
    assert payload["tenant_id"] == tenant_id
    assert payload["sub"] == user_id


def test_login_unverified_email_rejected(client):
    client.post(
        "/auth/register",
        json={
            "full_name": "Pending",
            "email": "pending@gmail.com",
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
            "account_type": "individual",
        },
    )
    r = login(client, "pending@gmail.com")
    assert r.status_code == 403


def test_login_unknown_email_rejected(client):
    r = login(client, "ghost@gmail.com")
    assert r.status_code == 401


def test_login_wrong_password_rejected(client):
    register_verified_individual(client, "wrongpass@gmail.com")
    r = login(client, "wrongpass@gmail.com", password="WrongPass1!")
    assert r.status_code == 401


def test_login_tokens_have_minimal_claims(client):
    register_verified_individual(client, "claims@gmail.com")
    r = login(client, "claims@gmail.com")
    assert r.status_code == 200

    access = decode_token(r.json()["access_token"], TokenType.ACCESS)
    assert set(access).issubset({"sub", "type", "iat", "exp", "iss", "role", "tenant_id"})

    refresh = decode_token(r.cookies.get("refresh_token"), TokenType.REFRESH)
    assert set(refresh).issubset({"sub", "type", "iat", "exp", "iss", "jti"})