"""Internal notification API.

Exposes ``send_*`` email operations to the other microservices over HTTP.
Protected by the shared internal API key (``X-Internal-API-Key`` header).
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr, Field

from notification.services.notification_service import notification_service
from shared.dependencies.internal_auth import create_internal_auth
from notification.config import notification_settings

router = APIRouter(prefix="/internal/emails", tags=["internal-emails"])

verify_internal = create_internal_auth(notification_settings.INTERNAL_API_KEY)


class EmailRequest(BaseModel):
    email: EmailStr


class OtpEmailRequest(EmailRequest):
    otp_code: str = Field(min_length=6, max_length=8)
    purpose: str


class WelcomeEmailRequest(EmailRequest):
    full_name: str = Field(min_length=1, max_length=255)


class InviteEmailRequest(EmailRequest):
    tenant_name: str = Field(min_length=1, max_length=255)
    invite_token: str


class PasswordResetEmailRequest(EmailRequest):
    otp_code: str = Field(min_length=6, max_length=8)


class AdminEmailRequest(EmailRequest):
    full_name: str = Field(min_length=1, max_length=255)
    tenant_name: str


class ProfileCompletionEmailRequest(EmailRequest):
    tenant_name: str = Field(min_length=1, max_length=255)


class InvitationAcceptedEmailRequest(EmailRequest):
    tenant_name: str = Field(min_length=1, max_length=255)


@router.post("/otp", status_code=200)
def send_otp(
    payload: OtpEmailRequest,
    api_key: str = Depends(verify_internal),
):
    notification_service.send_otp_email(payload.email, payload.otp_code, payload.purpose)
    return {"status": "sent"}


@router.post("/welcome", status_code=200)
def send_welcome(
    payload: WelcomeEmailRequest,
    api_key: str = Depends(verify_internal),
):
    notification_service.send_welcome_email(payload.email, payload.full_name)
    return {"status": "sent"}


@router.post("/invite", status_code=200)
def send_invite(
    payload: InviteEmailRequest,
    api_key: str = Depends(verify_internal),
):
    notification_service.send_invite_email(
        payload.email, payload.tenant_name, payload.invite_token
    )
    return {"status": "sent"}


@router.post("/password-reset", status_code=200)
def send_password_reset(
    payload: PasswordResetEmailRequest,
    api_key: str = Depends(verify_internal),
):
    notification_service.send_password_reset_email(payload.email, payload.otp_code)
    return {"status": "sent"}


@router.post("/password-reset-confirmation", status_code=200)
def send_password_reset_confirmation(
    payload: EmailRequest,
    api_key: str = Depends(verify_internal),
):
    notification_service.send_password_reset_confirmation(payload.email)
    return {"status": "sent"}


@router.post("/user-activated", status_code=200)
def send_user_activated(
    payload: WelcomeEmailRequest,
    api_key: str = Depends(verify_internal),
):
    notification_service.send_user_activated_email(payload.email, payload.full_name)
    return {"status": "sent"}


@router.post("/login-alert", status_code=200)
def send_login_alert(
    payload: WelcomeEmailRequest,
    api_key: str = Depends(verify_internal),
):
    notification_service.send_login_alert_email(payload.email, payload.full_name)
    return {"status": "sent"}


@router.post("/organization-created", status_code=200)
def send_organization_created(
    payload: ProfileCompletionEmailRequest,
    api_key: str = Depends(verify_internal),
):
    notification_service.send_organization_created_email(payload.email, payload.tenant_name)
    return {"status": "sent"}


@router.post("/tenant-admin-created", status_code=200)
def send_tenant_admin_created(
    payload: AdminEmailRequest,
    api_key: str = Depends(verify_internal),
):
    notification_service.send_tenant_admin_created_email(
        payload.email, payload.full_name, payload.tenant_name
    )
    return {"status": "sent"}


@router.post("/profile-completion", status_code=200)
def send_profile_completion(
    payload: ProfileCompletionEmailRequest,
    api_key: str = Depends(verify_internal),
):
    notification_service.send_profile_completion_email(payload.email, payload.tenant_name)
    return {"status": "sent"}


@router.post("/invitation-accepted", status_code=200)
def send_invitation_accepted(
    payload: InvitationAcceptedEmailRequest,
    api_key: str = Depends(verify_internal),
):
    notification_service.send_invitation_accepted_email(payload.email, payload.tenant_name)
    return {"status": "sent"}