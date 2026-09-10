import logging
from datetime import timedelta
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import TokenType, OtpPurpose, UserRole, UserStatus, UserType
from app.core.emails import validate_individual_email, validate_organization_email
from app.core.exceptions import (
    CredentialsInactiveError,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    NotFoundError,
    OtpInvalidError,
    ValidationError_,
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_jti,
    hash_password,
    utcnow,
    validate_password,
    verify_password,
)
from app.repositories.auth_repo import AuthRepository
from app.services.otp_service import OtpService
from app.services.user_service import UserService

logger = logging.getLogger(__name__)


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.auth_repo = AuthRepository(db)
        self.user_service = UserService(db)
        self.otp_service = OtpService(db)
        if settings.SERVICE_MODE == "microservices":
            # Tenants and notifications are other microservices: reach them
            # over HTTP using the shared internal API key.
            from shared.clients.notification_client import NotificationClient
            from shared.clients.tenant_client import TenantClient

            self.tenant_service = TenantClient(
                base_url=settings.TENANT_SERVICE_URL,
                api_key=settings.INTERNAL_API_KEY,
            )
            self.notification_service = NotificationClient(
                base_url=settings.NOTIFICATION_SERVICE_URL,
                api_key=settings.INTERNAL_API_KEY,
            )
        else:
            # Monolith mode: in-process services sharing this database session.
            from notification.services.notification_service import notification_service
            from tenant.services.tenant_service import TenantService

            self.tenant_service = TenantService(db)
            self.notification_service = notification_service

    # ---------- Validation helpers ----------
    def _validate_email(self, email: str) -> None:
        # Pydantic EmailStr enforces format at boundary; this is a business check.
        if email.count("@") != 1:
            raise ValidationError_("Invalid email address")

    def _validate_password(self, password: str) -> None:
        validate_password(password)

    # ---------- Registration ----------
    def register_individual(self, email: str, password: str, full_name: str):
        self._validate_email(email)
        self._validate_password(password)
        if self.user_service.get_by_email(email):
            raise EmailAlreadyExistsError()

        user = self.user_service.create_user(
            email=email,
            full_name=full_name,
            user_type=UserType.INDIVIDUAL,
            role=UserRole.INDIVIDUAL,
            status=UserStatus.PENDING,
        )
        self.auth_repo.create_credentials(
            user_id=user.id,
            email=email,
            password_hash=hash_password(password),
            is_active=False,
        )
        self._issue_otp(email, OtpPurpose.EMAIL_VERIFY)
        return user

    def begin_individual_registration(
        self, full_name: str, email: str, password: str, confirm_password: str
    ) -> dict:
        """Start Individual registration: validate inputs, persist a pending
        (inactive) user + hashed credentials, issue an OTP, and return the OTP
        challenge data (one-time code + otp_id) plus the registration cookie JWT.

        The final account is NOT activated here; a pending record is created so
        the (hashed) password survives until OTP verification completes it.
        """
        if confirm_password != password:
            raise ValidationError_("password and confirm_password do not match")
        # Validate the personal email first (only personal domains allowed).
        email = validate_individual_email(email)
        self._validate_email(email)
        self._validate_password(password)
        if self.user_service.get_by_email(email):
            raise EmailAlreadyExistsError()

        user = self.user_service.create_user(
            email=email,
            full_name=full_name,
            user_type=UserType.INDIVIDUAL,
            role=UserRole.INDIVIDUAL,
            status=UserStatus.PENDING,
        )
        self.auth_repo.create_credentials(
            user_id=user.id,
            email=email,
            password_hash=hash_password(password),
            is_active=False,
        )
        return self._issue_challenge(email)

    def begin_organization_registration(
        self, full_name: str, email: str, password: str, confirm_password: str, org_name: str
    ) -> dict:
        """Start Organization registration: validate inputs, persist a pending
        (inactive) tenant + admin user + hashed credentials, issue an OTP, and
        return the challenge data + OTP cookie JWT.

        The final ACTIVE tenant/admin account is NOT created here; only pending
        records are persisted so the (hashed) password survives to verification.
        """
        if confirm_password != password:
            raise ValidationError_("password and confirm_password do not match")
        # Official/business email (personal domains rejected).
        email = validate_organization_email(email)
        self._validate_email(email)
        self._validate_password(password)
        org_name = org_name.strip()
        if not org_name:
            raise ValidationError_("organization_name is required")
        if self.user_service.get_by_email(email):
            raise EmailAlreadyExistsError()
        try:
            self.tenant_service.get_tenant_by_org_email(email)
            raise EmailAlreadyExistsError()
        except NotFoundError:
            pass

        self.tenant_service.create_tenant(name=org_name, org_email=email)
        tenant = self.tenant_service.get_tenant_by_org_email(email)
        user = self.user_service.create_user(
            email=email,
            full_name=full_name,
            user_type=UserType.TENANT_ADMIN,
            role=UserRole.TENANT_ADMIN,
            status=UserStatus.PENDING,
            tenant_id=tenant.id,
        )
        self.tenant_service.add_admin(tenant.id, user.id)
        self.auth_repo.create_credentials(
            user_id=user.id,
            email=email,
            password_hash=hash_password(password),
            is_active=False,
        )
        return self._issue_challenge(email)

    def _issue_challenge(self, email: str) -> dict:
        """Issue + store an OTP, mint the OTP cookie JWT, send the email, and
        return the challenge payload plus the cookie token.
        """
        self.db.commit()
        issued = self.otp_service.issue_otp(email, OtpPurpose.REGISTRATION)
        otp_token = self.otp_service.create_otp_token(
            email, OtpPurpose.REGISTRATION, issued.otp_id
        )
        self.notification_service.send_otp_email(email, issued.code, OtpPurpose.REGISTRATION.value)
        logger.info("Registration started: email=%s", _mask_email(email))
        return {
            "email": email,
            "otp_code": issued.code,
            "otp_token": otp_token,
            "expires_in": settings.OTP_EXPIRE_MINUTES * 60,
        }

    def complete_registration(self, otp: str, otp_token: str) -> dict:
        """Complete a pending registration by validating the OTP challenge and
        activating the appropriate account type.

        Validates the otp_token cookie (purpose + expiry), verifies the submitted
        OTP (including retry count), then dispatches to the Individual or
        Organization activation path based on the pending user's type.
        """
        try:
            payload = self.otp_service.validate_otp_token(
                otp_token, OtpPurpose.REGISTRATION
            )
        except ValueError:
            raise OtpInvalidError()
        email = payload.get("sub")
        if not email:
            raise OtpInvalidError()

        # OtpService.verify_otp validates expiry + retry count and verifies the code.
        verified_id = self.otp_service.verify_otp(
            email, otp, OtpPurpose.REGISTRATION
        )
        # Bind the cookie to the verified OTP: a stale (pre-resend) cookie whose
        # txn points at a revoked OTP must not verify against a newer code.
        if payload.get("txn") != verified_id:
            raise OtpInvalidError()

        user = self.user_service.get_by_email(email)
        if not user:
            raise InvalidCredentialsError()
        if user.user_type == UserType.INDIVIDUAL:
            return self._complete_individual(email, user)
        if user.user_type == UserType.TENANT_ADMIN:
            return self._complete_organization(email, user)
        raise OtpInvalidError()

    def _complete_individual(self, email: str, user) -> dict:
        self.user_service.activate_user(user.id)
        self.auth_repo.set_active(user.id, True)
        self.auth_repo.mark_email_verified(user.id)
        self.db.commit()

        self.notification_service.send_welcome_email(email, user.full_name)
        self.notification_service.send_user_activated_email(email, user.full_name)

        logger.info(
            "Individual registration completed: email=%s user_id=%s",
            _mask_email(email), user.id,
        )
        return self._build_auth_response(user)

    def _complete_organization(self, email: str, user) -> dict:
        # Activate tenant + admin through their owning services (atomic: this
        # session commits or rolls back as a unit, so no partial state).
        tenant = self.tenant_service.get_tenant_by_org_email(email)
        self.tenant_service.activate_tenant_account(tenant.id)
        self.user_service.activate_user(user.id)
        self.auth_repo.set_active(user.id, True)
        self.auth_repo.mark_email_verified(user.id)
        self.db.commit()

        self.notification_service.send_welcome_email(email, user.full_name)
        self.notification_service.send_user_activated_email(email, user.full_name)
        self.notification_service.send_organization_created_email(email, tenant.name)
        self.notification_service.send_tenant_admin_created_email(
            email, user.full_name, tenant.name
        )

        logger.info(
            "Organization registration completed: email=%s tenant_id=%s user_id=%s",
            _mask_email(email), tenant.id, user.id,
        )
        return self._build_auth_response(user)

    def register_tenant(
        self, email: str, password: str, full_name: str, org_name: str, org_email: str
    ):
        self._validate_email(email)
        self._validate_email(org_email)
        self._validate_password(password)
        if self.user_service.get_by_email(email):
            raise EmailAlreadyExistsError()

        self.tenant_service.create_tenant(name=org_name, org_email=org_email)
        tenant = self.tenant_service.get_tenant_by_org_email(org_email)

        user = self.user_service.create_user(
            email=email,
            full_name=full_name,
            user_type=UserType.TENANT_ADMIN,
            role=UserRole.TENANT_ADMIN,
            status=UserStatus.PENDING,
            tenant_id=tenant.id,
        )
        self.tenant_service.add_admin(tenant.id, user.id)
        self.auth_repo.create_credentials(
            user_id=user.id,
            email=email,
            password_hash=hash_password(password),
            is_active=False,
        )
        self._issue_otp(email, OtpPurpose.EMAIL_VERIFY)
        return user

    # ---------- OTP ----------
    def _issue_otp(self, email: str, purpose: OtpPurpose) -> str:
        code = self.otp_service.issue_otp(email, purpose).code
        if purpose in (
            OtpPurpose.PASSWORD_RESET,
            OtpPurpose.FORGOT_PASSWORD,
        ):
            self.notification_service.send_password_reset_email(email, code)
        else:
            self.notification_service.send_otp_email(email, code, purpose.value)
        return code

    def resend_otp(self, email: str, purpose: OtpPurpose) -> None:
        code = self.otp_service.issue_otp(email, purpose).code
        if purpose == OtpPurpose.PASSWORD_RESET or purpose == OtpPurpose.FORGOT_PASSWORD:
            self.notification_service.send_password_reset_email(email, code)
        else:
            self.notification_service.send_otp_email(email, code, purpose.value)

    def resend_otp_from_cookie(self, otp_token: str) -> str:
        """Resend the OTP for the purpose bound in the otp_token cookie.

        Determines email + purpose from the secure OTP transaction, enforces
        resend cooldown/limits, and returns a new OTP JWT for a fresh cookie.
        """
        try:
            payload = self.otp_service.validate_otp_token(otp_token)
        except ValueError:
            raise OtpInvalidError()
        email = payload.get("sub")
        purpose = payload.get("purpose")
        if not email or not purpose:
            raise OtpInvalidError()
        try:
            purpose_enum = OtpPurpose(purpose)
        except ValueError:
            raise OtpInvalidError()

        issue = self.otp_service.resend_otp(email, purpose_enum)
        if purpose_enum in (
            OtpPurpose.PASSWORD_RESET,
            OtpPurpose.FORGOT_PASSWORD,
        ):
            self.notification_service.send_password_reset_email(email, issue.code)
        else:
            self.notification_service.send_otp_email(
                email, issue.code, purpose_enum.value
            )
        return self.otp_service.create_otp_token(
            email, purpose_enum, issue.otp_id
        )

    def verify_otp(self, email: str, otp: str, purpose: OtpPurpose):
        return self.otp_service.verify_otp(email, otp, purpose)

    def complete_email_verification(self, email: str, otp: str) -> dict:
        self.verify_otp(email, otp, OtpPurpose.EMAIL_VERIFY)
        user = self.user_service.get_by_email(email)
        if not user:
            raise InvalidCredentialsError()
        self.auth_repo.set_active(user.id, True)
        self.auth_repo.mark_email_verified(user.id)
        self.user_service.activate_user(user.id)
        self.notification_service.send_welcome_email(email, user.full_name)
        self.notification_service.send_user_activated_email(email, user.full_name)
        return self._build_auth_response(user)

    # ---------- Login ----------
    def login(self, email: str, password: str) -> dict:
        user = self.user_service.get_by_email(email)
        creds = self.auth_repo.get_by_email(email) if user else None
        if not user or not creds:
            raise InvalidCredentialsError()
        if not verify_password(password, creds.password_hash):
            raise InvalidCredentialsError()
        if (
            not creds.is_active
            or user.status != UserStatus.ACTIVE
            or not creds.email_verified
        ):
            raise CredentialsInactiveError()
        # Best-effort security notification: a transient email failure must
        # never block authentication.
        try:
            self.notification_service.send_login_alert_email(email, user.full_name)
        except Exception:
            logger.warning(
                "Login security notification failed for %s",
                _mask_email(email),
            )
        return self._build_auth_response(user)

    # ---------- Tokens / cookies ----------
    def _build_auth_response(self, user) -> dict:
        access_token = create_access_token(user.id, user.role.value, user.tenant_id)
        refresh_token, jti = create_refresh_token(user.id)
        expires_at = utcnow() + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
        self.auth_repo.create_refresh_token(
            user_id=user.id, token_hash=hash_jti(jti), expires_at=expires_at
        )
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role.value,
                "user_type": user.user_type.value,
                "status": user.status.value,
                "tenant_id": user.tenant_id,
            },
        }

    def refresh(self, refresh_token: str) -> dict:
        try:
            payload = decode_token(refresh_token, TokenType.REFRESH)
        except ValueError:
            raise InvalidCredentialsError()
        user_id = payload.get("sub")
        jti = payload.get("jti")
        if not user_id or not jti:
            raise InvalidCredentialsError()

        record = self.auth_repo.get_refresh_token(hash_jti(jti))
        if not record or record.is_revoked or record.expires_at < utcnow():
            raise InvalidCredentialsError()

        user = self.user_service.get_by_id(user_id)
        if not user or user.status != UserStatus.ACTIVE:
            raise CredentialsInactiveError()

        # Rotate: revoke old, issue new
        self.auth_repo.revoke_refresh_token(record)
        access_token = create_access_token(user.id, user.role.value, user.tenant_id)
        refresh_token, new_jti = create_refresh_token(user.id)
        new_expires = utcnow() + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
        self.auth_repo.create_refresh_token(
            user_id=user.id,
            token_hash=hash_jti(new_jti),
            expires_at=new_expires,
            rotated_from=record.id,
        )
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role.value,
                "user_type": user.user_type.value,
                "status": user.status.value,
                "tenant_id": user.tenant_id,
            },
        }

    def logout(self, refresh_token: Optional[str]) -> None:
        if not refresh_token:
            return
        try:
            payload = decode_token(refresh_token)
            user_id = payload.get("sub")
            if user_id:
                self.auth_repo.revoke_all_user_tokens(user_id)
        except ValueError:
            pass

    # ---------- Invitation acceptance ----------
    def accept_invitation(self, token: str, full_name: str, password: str):
        self._validate_password(password)
        user, invite = self.tenant_service.accept_invitation(
            token=token, full_name=full_name
        )
        if self.auth_repo.get_by_email(user.email):
            from app.core.exceptions import ConflictError
            raise ConflictError("Account already exists")
        self.auth_repo.create_credentials(
            user_id=user.id,
            email=user.email,
            password_hash=hash_password(password),
            is_active=False,
        )
        self._issue_otp(user.email, OtpPurpose.EMAIL_VERIFY)
        return user

    # ---------- Forgot / reset password ----------
    def forgot_password(self, email: str) -> Optional[str]:
        """Issue a forgot-password OTP for a registered email.

        Returns a short-lived OTP JWT (to set as the otp_token cookie) when an
        account exists, otherwise None. Callers must respond identically in both
        cases to avoid user enumeration.
        """
        user = self.user_service.get_by_email(email)
        if not user:
            return None
        issue = self.otp_service.issue_otp(email, OtpPurpose.FORGOT_PASSWORD)
        self.notification_service.send_password_reset_email(email, issue.code)
        return self.otp_service.create_otp_token(
            email, OtpPurpose.FORGOT_PASSWORD, issue.otp_id
        )

    def verify_forgot_otp(self, otp_token: str, otp: str) -> str:
        """Validate the forgot-password OTP JWT and code.

        On success the OTP is consumed and a short-lived password-reset state
        token is returned; reset-password requires this token.
        """
        try:
            payload = self.otp_service.validate_otp_token(
                otp_token, OtpPurpose.FORGOT_PASSWORD
            )
        except ValueError:
            raise OtpInvalidError()
        email = payload.get("sub")
        txn = payload.get("txn")
        if not email or not txn:
            raise OtpInvalidError()
        if not self.user_service.get_by_email(email):
            raise OtpInvalidError()
        verified_id = self.otp_service.verify_otp(
            email, otp, OtpPurpose.FORGOT_PASSWORD
        )
        if verified_id != txn:
            raise OtpInvalidError()
        return self.otp_service.create_otp_token(
            email, OtpPurpose.PASSWORD_RESET, None
        )

    def reset_password(
        self, reset_token: str, new_password: str, confirm_password: str
    ) -> None:
        if new_password != confirm_password:
            raise ValidationError_("password and confirm_password do not match")
        self._validate_password(new_password)
        try:
            payload = self.otp_service.validate_otp_token(
                reset_token, OtpPurpose.PASSWORD_RESET
            )
        except ValueError:
            raise OtpInvalidError()
        email = payload.get("sub")
        if not email:
            raise OtpInvalidError()
        user = self.user_service.get_by_email(email)
        if not user:
            raise OtpInvalidError()
        self.auth_repo.update_password(user.id, hash_password(new_password))
        self.auth_repo.revoke_active_otps(
            email, OtpPurpose.FORGOT_PASSWORD.value
        )
        self.auth_repo.revoke_all_user_tokens(user.id)
        self.notification_service.send_password_reset_confirmation(email)


def _mask_email(email: str) -> str:
    """Mask an email for logging so no sensitive data is written."""
    if not email or "@" not in email:
        return "***"
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        visible = local[0] if local else ""
        return f"{visible}***@{domain}"
    return f"{local[:2]}***@{domain}"
