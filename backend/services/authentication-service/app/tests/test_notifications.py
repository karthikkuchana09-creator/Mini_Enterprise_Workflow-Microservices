"""Notification integration tests.

Verifies that authentication/account events fan out through the existing
notification service (NotificationService singleton -> SMTP or dev-mode email
logs), one notification per relevant lifecycle event, and that secrets (OTP
codes, invite tokens, access/refresh tokens) are never persisted in logs.
"""
import logging

from notification.services.notification_service import notification_service

from app.core.constants import UserRole
from app.tests.conftest import set_otp

PASSWORD = "StrongPass1!"


def log_text(caplog) -> str:
    return "\n".join(
        r.getMessage()
        for r in caplog.records
        if r.name == "ecwf.notification" and "[email:dev]" in r.getMessage()
    )


def assert_email_sent(caplog, fragment: str, to: str = None) -> str:
    needle = fragment.lower()
    for r in caplog.records:
        if r.name != "ecwf.notification":
            continue
        msg = r.getMessage()
        if "[email:dev]" not in msg:
            continue
        if needle in msg.lower() and (to is None or f"To={to}" in msg):
            return msg
    raise AssertionError(
        f"no email containing {fragment!r} in notification logs:\n{log_text(caplog)}"
    )


def begin_individual(client, email):
    r = client.post(
        "/auth/register",
        json={
            "account_type": "individual",
            "full_name": "Test Person",
            "email": email,
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert r.status_code == 201
    return r.json()


def begin_org(client, email, org_name="Acme Inc"):
    r = client.post(
        "/auth/register",
        json={
            "account_type": "organization",
            "full_name": "Org Boss",
            "email": email,
            "password": PASSWORD,
            "confirm_password": PASSWORD,
            "organization_name": org_name,
        },
    )
    assert r.status_code == 201
    return r.json()


def verify_registration(client, email, code="111111"):
    set_otp(email, code, purpose="registration")
    r = client.post("/auth/verify-otp", json={"otp": code})
    assert r.status_code == 200
    return r.json()


def test_individual_registration_otp_and_activation_emails(client, caplog):
    caplog.set_level(logging.INFO, logger="ecwf.notification")
    begin_individual(client, "notif-ind@gmail.com")

    otp_email = assert_email_sent(caplog, "verification code", to="notif-ind@gmail.com")
    assert "***" in otp_email

    verify_registration(client, "notif-ind@gmail.com")
    assert_email_sent(caplog, "Welcome to ECWF", to="notif-ind@gmail.com")
    assert_email_sent(caplog, "account activated", to="notif-ind@gmail.com")


def test_otp_code_never_persisted_in_logs(client, caplog, monkeypatch):
    caplog.set_level(logging.INFO, logger="ecwf.notification")
    real_send = notification_service.send_otp_email
    sent_codes = []

    def recording(email, otp_code, purpose):
        sent_codes.append(otp_code)
        real_send(email, otp_code, purpose)

    monkeypatch.setattr(notification_service, "send_otp_email", recording)
    begin_individual(client, "notif-otp-leak@gmail.com")

    assert sent_codes, "an OTP email must have been generated"
    text = log_text(caplog)
    for code in sent_codes:
        assert code not in text, "OTP value leaked into notification logs"
    assert "***" in text


def test_organization_registration_emails(client, caplog):
    caplog.set_level(logging.INFO, logger="ecwf.notification")
    begin_org(client, "notif-org@corp.com", "Acme Inc")

    assert_email_sent(caplog, "verification code", to="notif-org@corp.com")

    data = verify_registration(client, "notif-org@corp.com")
    assert data["user"]["role"] == UserRole.TENANT_ADMIN.value
    assert_email_sent(caplog, "Welcome to ECWF", to="notif-org@corp.com")
    assert_email_sent(caplog, "account activated", to="notif-org@corp.com")
    assert_email_sent(caplog, "organization is ready", to="notif-org@corp.com")
    assert_email_sent(caplog, "administrator on ECWF", to="notif-org@corp.com")


def test_profile_completion_email_sent_once(client, caplog, monkeypatch):
    caplog.set_level(logging.INFO, logger="ecwf.notification")
    begin_org(client, "notif-profile@corp.com", "Profile Corp")
    data = verify_registration(client, "notif-profile@corp.com")
    access = data["access_token"]
    tenant_id = data["user"]["tenant_id"]

    real = notification_service.send_profile_completion_email
    calls = []

    def recording(email, tenant_name):
        calls.append((email, tenant_name))
        real(email, tenant_name)

    monkeypatch.setattr(notification_service, "send_profile_completion_email", recording)

    headers = {"Authorization": f"Bearer {access}"}
    first = client.patch(
        f"/tenants/{tenant_id}/profile", headers=headers, json={"name": "Profile Corp"}
    )
    assert first.status_code == 200
    assert first.json()["profile_completed_at"] is not None

    second = client.patch(
        f"/tenants/{tenant_id}/profile", headers=headers, json={"name": "Profile Corp 2"}
    )
    assert second.status_code == 200

    assert calls == [("notif-profile@corp.com", "Profile Corp")]
    assert_email_sent(caplog, "Organization profile completed", to="notif-profile@corp.com")


def test_login_security_email(client, caplog):
    caplog.set_level(logging.INFO, logger="ecwf.notification")
    begin_individual(client, "notif-login@gmail.com")
    verify_registration(client, "notif-login@gmail.com")

    r = client.post("/auth/login", json={"email": "notif-login@gmail.com", "password": PASSWORD})
    assert r.status_code == 200

    assert_email_sent(caplog, "New sign-in", to="notif-login@gmail.com")
    text = log_text(caplog)
    assert r.json()["access_token"] not in text
    refresh = r.cookies.get("refresh_token")
    assert refresh and refresh not in text


def test_forgot_and_reset_emails(client, caplog, monkeypatch):
    caplog.set_level(logging.INFO, logger="ecwf.notification")
    begin_individual(client, "notif-reset@gmail.com")
    verify_registration(client, "notif-reset@gmail.com")

    real_send = notification_service.send_password_reset_email
    sent_codes = []

    def recording(email, otp_code):
        sent_codes.append(otp_code)
        real_send(email, otp_code)

    monkeypatch.setattr(notification_service, "send_password_reset_email", recording)

    r = client.post("/auth/forgot-password", json={"email": "notif-reset@gmail.com"})
    assert r.status_code == 200
    assert sent_codes, "a password-reset OTP email must have been generated"
    text = log_text(caplog)
    assert all(c not in text for c in sent_codes), "OTP value leaked into notification logs"

    assert_email_sent(caplog, "password reset code", to="notif-reset@gmail.com")

    set_otp("notif-reset@gmail.com", "444444", purpose="forgot_password")
    assert client.post(
        "/auth/verify-forgot-otp", json={"otp": "444444"}
    ).status_code == 200
    assert client.post(
        "/auth/reset-password",
        json={"new_password": "NewPass9!", "confirm_password": "NewPass9!"},
    ).status_code == 200
    assert_email_sent(caplog, "password changed", to="notif-reset@gmail.com")


def test_invite_and_accept_emails(client, caplog, monkeypatch):
    caplog.set_level(logging.INFO, logger="ecwf.notification")
    begin_org(client, "notif-boss@corp.com")
    data = verify_registration(client, "notif-boss@corp.com")
    access = data["access_token"]
    tenant_id = data["user"]["tenant_id"]
    headers = {"Authorization": f"Bearer {access}"}

    real_invite = notification_service.send_invite_email
    invites = []

    def invite_recording(email, tenant_name, invite_token):
        invites.append((email, tenant_name, invite_token))
        real_invite(email, tenant_name, invite_token)

    monkeypatch.setattr(notification_service, "send_invite_email", invite_recording)

    r = client.post(
        f"/tenants/{tenant_id}/invitations",
        headers=headers,
        json={"email": "notif-emp@corp.com", "role": "tenant_user"},
    )
    assert r.status_code == 201
    assert invites, "an invite email must have been generated"
    raw_token = invites[0][2]
    assert raw_token not in log_text(caplog), "invite token leaked into notification logs"
    assert_email_sent(caplog, "Invitation to join", to="notif-emp@corp.com")

    real_accepted = notification_service.send_invitation_accepted_email
    accepted = []

    def accepted_recording(email, tenant_name):
        accepted.append((email, tenant_name))
        real_accepted(email, tenant_name)

    monkeypatch.setattr(notification_service, "send_invitation_accepted_email", accepted_recording)

    accept = client.post(
        "/auth/accept-invitation",
        json={
            "token": raw_token,
            "full_name": "New Employee",
            "password": "NewEmpPass1!",
        },
    )
    assert accept.status_code == 201
    assert accepted == [("notif-emp@corp.com", "Acme Inc")]
    assert_email_sent(caplog, "You joined", to="notif-emp@corp.com")
    # EMAIL_VERIFY OTP generated for the accepted tenant user.
    assert_email_sent(caplog, "verification code", to="notif-emp@corp.com")