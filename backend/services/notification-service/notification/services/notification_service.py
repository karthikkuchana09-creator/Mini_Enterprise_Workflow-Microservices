import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from notification.config import notification_settings

logger = logging.getLogger("ecwf.notification")


class NotificationService:
    """Handles email notifications and event fan-out.

    Emails are sent via SMTP when configured; otherwise (dev mode) they are
    logged to the application logger so flows remain testable. Secrets
    (OTP codes, invitation tokens) are scrubbed from dev-mode logs: they are
    only ever delivered through the email transport itself.
    """

    def _send_email(
        self, to: str, subject: str, html_body: str, redact: tuple = ()
    ) -> None:
        if not notification_settings.SMTP_HOST:
            log_body = html_body
            for secret in redact:
                log_body = log_body.replace(secret, "***")
            logger.info(
                "[email:dev] To=%s Subject=%r Body=%r",
                to,
                subject,
                log_body,
            )
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = notification_settings.SMTP_FROM_EMAIL
        msg["To"] = to
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(notification_settings.SMTP_HOST, notification_settings.SMTP_PORT) as server:
            if notification_settings.SMTP_USER:
                server.starttls()
                server.login(notification_settings.SMTP_USER, notification_settings.SMTP_PASSWORD)
            server.sendmail(notification_settings.SMTP_FROM_EMAIL, [to], msg.as_string())

    def send_otp_email(self, email: str, otp_code: str, purpose: str) -> None:
        subject = "Your ECWF verification code"
        body = f"<p>Your ECWF {purpose} code is <b>{otp_code}</b>. It expires shortly.</p>"
        self._send_email(email, subject, body, redact=(otp_code,))

    def send_welcome_email(self, email: str, full_name: str) -> None:
        subject = "Welcome to ECWF"
        body = f"<p>Hi {full_name}, your account has been activated. Welcome aboard!</p>"
        self._send_email(email, subject, body)

    def send_invite_email(self, email: str, tenant_name: str, invite_token: str) -> None:
        subject = f"Invitation to join {tenant_name}"
        body = f"<p>You've been invited to join <b>{tenant_name}</b> on ECWF.</p><p>Use token: <b>{invite_token}</b> to accept.</p>"
        self._send_email(email, subject, body, redact=(invite_token,))

    def send_password_reset_email(self, email: str, otp_code: str) -> None:
        subject = "ECWF password reset code"
        body = f"<p>Your ECWF password reset code is <b>{otp_code}</b>.</p>"
        self._send_email(email, subject, body, redact=(otp_code,))

    def send_password_reset_confirmation(self, email: str) -> None:
        subject = "ECWF password changed"
        body = "<p>Your ECWF password was successfully changed.</p>"
        self._send_email(email, subject, body)

    def send_user_activated_email(self, email: str, full_name: str) -> None:
        subject = "ECWF account activated"
        body = f"<p>Hi {full_name}, your account is now active.</p>"
        self._send_email(email, subject, body)

    def send_login_alert_email(self, email: str, full_name: str) -> None:
        subject = "New sign-in to your ECWF account"
        body = (
            f"<p>Hi {full_name}, there was a new sign-in to your ECWF account. "
            "If this wasn't you, please contact support immediately.</p>"
        )
        self._send_email(email, subject, body)

    def send_organization_created_email(self, email: str, tenant_name: str) -> None:
        subject = "Your organization is ready on ECWF"
        body = (
            f"<p>Your organization <b>{tenant_name}</b> has been created and is "
            "now active on ECWF.</p>"
        )
        self._send_email(email, subject, body)

    def send_tenant_admin_created_email(
        self, email: str, full_name: str, tenant_name: str
    ) -> None:
        subject = "You are now an administrator on ECWF"
        body = (
            f"<p>Hi {full_name}, you have been set up as an administrator for "
            f"<b>{tenant_name}</b>. Welcome!</p>"
        )
        self._send_email(email, subject, body)

    def send_profile_completion_email(self, email: str, tenant_name: str) -> None:
        subject = "Organization profile completed"
        body = (
            f"<p>Your organization profile for <b>{tenant_name}</b> is complete. "
            "You can now access the dashboard.</p>"
        )
        self._send_email(email, subject, body)

    def send_invitation_accepted_email(self, email: str, tenant_name: str) -> None:
        subject = f"You joined {tenant_name} on ECWF"
        body = (
            f"<p>You've been added to <b>{tenant_name}</b>. Complete email "
            "verification to activate your account.</p>"
        )
        self._send_email(email, subject, body)


notification_service = NotificationService()