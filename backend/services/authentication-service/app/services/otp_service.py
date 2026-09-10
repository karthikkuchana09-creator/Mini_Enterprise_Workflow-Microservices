"""Reusable OTP subsystem.

Encapsulates secure OTP generation, storage, verification, retry handling,
resend (with cooldown), and short-lived OTP JWT creation/validation for the
registration and forgot-password flows.
"""
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import OtpPurpose, TokenType
from app.core.exceptions import (
    OtpInvalidError,
    OtpMaxAttemptsError,
    OtpMaxResendError,
    OtpResendTooSoonError,
)
from app.core.security import (
    create_otp_token,
    generate_otp,
    hash_otp,
    utcnow,
    validate_otp_token,
    verify_password,
)
from app.repositories.auth_repo import AuthRepository


@dataclass
class OtpIssue:
    """Result of issuing an OTP: the one-time code and its storage id."""

    code: str
    otp_id: str


class OtpService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = AuthRepository(db)

    # ------------------------------------------------------------------
    # Generation & storage
    # ------------------------------------------------------------------
    def issue_otp(self, email: str, purpose: OtpPurpose) -> OtpIssue:
        """Generate and store a new OTP, invalidating any previous active one.

        The plaintext code is returned once for delivery and is never stored;
        only its hash is persisted. Returns the code and its storage id.
        """
        code = generate_otp()
        self.repo.revoke_active_otps(email, purpose.value)
        otp = self.repo.create_otp(
            email=email,
            purpose=purpose.value,
            otp_hash=hash_otp(code),
            expires_at=utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES),
            max_attempts=settings.OTP_MAX_ATTEMPTS,
        )
        return OtpIssue(code=code, otp_id=otp.id)

    # ------------------------------------------------------------------
    # Resend (with cooldown / abuse protection)
    # ------------------------------------------------------------------
    def resend_otp(self, email: str, purpose: OtpPurpose) -> OtpIssue:
        """Issue a fresh OTP, enforcing cooldown and resend-rate limits."""
        self._enforce_resend_cooldown(email, purpose)
        self._enforce_resend_cap(email, purpose)
        return self.issue_otp(email, purpose)

    def _enforce_resend_cooldown(self, email: str, purpose: OtpPurpose) -> None:
        last = self.repo.get_last_otp(email, purpose.value)
        if last is None:
            return
        elapsed = (utcnow() - last.created_at).total_seconds()
        if elapsed < settings.OTP_RESEND_COOLDOWN_SECONDS:
            raise OtpResendTooSoonError()

    def _enforce_resend_cap(self, email: str, purpose: OtpPurpose) -> None:
        """Limit total OTP issues per email+purpose inside the resend window."""
        since = utcnow() - timedelta(minutes=settings.OTP_RESEND_WINDOW_MINUTES)
        issued = self.repo.count_otps_issued(email, purpose.value, since)
        if issued >= settings.OTP_MAX_RESENDS:
            raise OtpMaxResendError()

    # ------------------------------------------------------------------
    # Verification & retry handling
    # ------------------------------------------------------------------
    def verify_otp(self, email: str, otp: str, purpose: OtpPurpose) -> str:
        """Verify an OTP code.

        On success the OTP is invalidated (used) and its id is returned.
        Raises OtpInvalidError / OtpMaxAttemptsError on failure. Wrong attempts
        increment the retry count; exceeding the maximum revokes the OTP.
        """
        record = self.repo.get_active_otp(email, purpose.value)
        if not record:
            raise OtpInvalidError()
        if not verify_password(otp, record.otp_hash):
            attempts = self.repo.increment_attempt(record)
            # Error responses cause the request session to roll back, so commit
            # the attempt counter / revocation before raising to persist it.
            if attempts >= record.max_attempts:
                self.repo.revoke_otp(record)
                self.db.commit()
                raise OtpMaxAttemptsError()
            self.db.commit()
            raise OtpInvalidError()
        self.repo.revoke_otp(record)
        return record.id

    # ------------------------------------------------------------------
    # OTP JWT
    # ------------------------------------------------------------------
    def create_otp_token(
        self, email: str, purpose: OtpPurpose, otp_id: str
    ) -> str:
        """Create a short-lived OTP JWT embedding purpose and transaction id."""
        return create_otp_token(
            user_id=email, purpose=purpose.value, txn=otp_id
        )

    def validate_otp_token(
        self, token: str, expected_purpose: Optional[OtpPurpose] = None
    ) -> dict:
        """Validate an OTP JWT, optionally checking its purpose.

        Returns the decoded payload on success; raises ValueError otherwise.
        """
        return validate_otp_token(
            token, expected_purpose.value if expected_purpose else None
        )
