from sqlalchemy import select

from app.core.security import hash_otp
from app.db.session import SessionLocal
from app.models.auth import AuthOtp
from app.tests.conftest import set_otp


def test_otp_max_attempts_invalidates(client):
    client.post(
        "/auth/register/individual",
        json={"email": "max@example.com", "password": "StrongPass1!", "full_name": "A"},
    )
    set_otp("max@example.com", "123456")
    # 3 failed attempts should exhaust then block
    for _ in range(3):
        r = client.post(
            "/auth/otp/verify",
            json={"email": "max@example.com", "otp": "000000", "purpose": "email_verify"},
        )
        assert r.status_code in (400, 429)
    # correct code must now fail (revoked)
    r = client.post(
        "/auth/otp/verify",
        json={"email": "max@example.com", "otp": "123456", "purpose": "email_verify"},
    )
    assert r.status_code == 400


def test_otp_resend_revokes_previous(client):
    client.post(
        "/auth/register/individual",
        json={"email": "res@example.com", "password": "StrongPass1!", "full_name": "A"},
    )
    set_otp("res@example.com", "111111")
    r = client.post("/auth/otp/resend", json={"email": "res@example.com", "purpose": "email_verify"})
    assert r.status_code == 200
    with SessionLocal() as db:
        otps = db.scalars(
            select(AuthOtp).where(AuthOtp.email == "res@example.com").order_by(AuthOtp.created_at)
        ).all()
    assert len(otps) == 2
    assert otps[0].revoked_at is not None
    assert otps[1].revoked_at is None
    # the old code should no longer validate
    r = client.post(
        "/auth/otp/verify",
        json={"email": "res@example.com", "otp": "111111", "purpose": "email_verify"},
    )
    assert r.status_code == 400


def test_otp_expired_rejected(client):
    client.post(
        "/auth/register/individual",
        json={"email": "exp@example.com", "password": "StrongPass1!", "full_name": "A"},
    )
    from datetime import datetime, timedelta, timezone
    from app.db.session import SessionLocal as SL
    from app.models.auth import AuthOtp as AO
    with SL() as db:
        otp = db.scalar(select(AO).where(AO.email == "exp@example.com"))
        otp.otp_hash = hash_otp("444444")
        otp.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
        db.commit()
    r = client.post(
        "/auth/otp/verify",
        json={"email": "exp@example.com", "otp": "444444", "purpose": "email_verify"},
    )
    assert r.status_code == 400
