"""HTTPX client for the notification-service internal email API.

All email sends are best-effort: a notification failure must never break the
auth/tenant operation that triggered it. Transport errors are logged, not
raised, which matches the login-alert behavior already present in auth-service.
"""
import logging
from typing import Optional

from shared.clients.internal_client import InternalApiClient

logger = logging.getLogger("ecwf.notification-client")


class NotificationClient(InternalApiClient):
    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0):
        super().__init__(base_url, api_key, "notification-service", timeout)

    def _send(self, path: str, json_body: Optional[dict]) -> None:
        try:
            self._json("POST", path, json_body=json_body)
        except Exception as exc:  # noqa: BLE001 - best-effort by design
            logger.warning("Notification call %s failed: %s", path, exc)

    def send_otp_email(self, email: str, otp_code: str, purpose: str) -> None:
        self._send(
            "/internal/emails/otp",
            {"email": email, "otp_code": otp_code, "purpose": purpose},
        )

    def send_welcome_email(self, email: str, full_name: str) -> None:
        self._send("/internal/emails/welcome", {"email": email, "full_name": full_name})

    def send_user_activated_email(self, email: str, full_name: str) -> None:
        self._send(
            "/internal/emails/user-activated",
            {"email": email, "full_name": full_name},
        )

    def send_login_alert_email(self, email: str, full_name: str) -> None:
        self._send(
            "/internal/emails/login-alert",
            {"email": email, "full_name": full_name},
        )

    def send_password_reset_email(self, email: str, otp_code: str) -> None:
        self._send(
            "/internal/emails/password-reset",
            {"email": email, "otp_code": otp_code},
        )

    def send_password_reset_confirmation(self, email: str) -> None:
        self._send("/internal/emails/password-reset-confirmation", {"email": email})

    def send_invite_email(self, email: str, tenant_name: str, invite_token: str) -> None:
        self._send(
            "/internal/emails/invite",
            {"email": email, "tenant_name": tenant_name, "invite_token": invite_token},
        )

    def send_organization_created_email(self, email: str, tenant_name: str) -> None:
        self._send(
            "/internal/emails/organization-created",
            {"email": email, "tenant_name": tenant_name},
        )

    def send_tenant_admin_created_email(
        self, email: str, full_name: str, tenant_name: str
    ) -> None:
        self._send(
            "/internal/emails/tenant-admin-created",
            {"email": email, "full_name": full_name, "tenant_name": tenant_name},
        )

    def send_profile_completion_email(self, email: str, tenant_name: str) -> None:
        self._send(
            "/internal/emails/profile-completion",
            {"email": email, "tenant_name": tenant_name},
        )

    def send_invitation_accepted_email(self, email: str, tenant_name: str) -> None:
        self._send(
            "/internal/emails/invitation-accepted",
            {"email": email, "tenant_name": tenant_name},
        )