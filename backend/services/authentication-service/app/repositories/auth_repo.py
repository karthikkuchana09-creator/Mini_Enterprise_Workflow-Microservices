from datetime import datetime
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import utcnow
from app.models.auth import AuthCredentials, AuthOtp, AuthRefreshToken


class AuthRepository:
    def __init__(self, db: Session):
        self.db = db

    # Credentials
    def create_credentials(
        self, user_id: str, email: str, password_hash: str, is_active: bool
    ) -> AuthCredentials:
        creds = AuthCredentials(
            user_id=user_id,
            email=email,
            password_hash=password_hash,
            is_active=is_active,
        )
        self.db.add(creds)
        self.db.flush()
        return creds

    def get_by_email(self, email: str) -> Optional[AuthCredentials]:
        return self.db.scalar(select(AuthCredentials).where(AuthCredentials.email == email))

    def get_by_user_id(self, user_id: str) -> Optional[AuthCredentials]:
        return self.db.scalar(
            select(AuthCredentials).where(AuthCredentials.user_id == user_id)
        )

    def update_password(self, user_id: str, password_hash: str) -> None:
        creds = self.get_by_user_id(user_id)
        if creds:
            creds.password_hash = password_hash
            self.db.flush()

    def set_active(self, user_id: str, active: bool) -> None:
        creds = self.get_by_user_id(user_id)
        if creds:
            creds.is_active = active
            self.db.flush()

    def mark_email_verified(self, user_id: str) -> None:
        creds = self.get_by_user_id(user_id)
        if creds:
            creds.email_verified = True
            self.db.flush()

    # OTP
    def create_otp(
        self,
        email: str,
        purpose: str,
        otp_hash: str,
        expires_at: datetime,
        max_attempts: int,
    ) -> AuthOtp:
        otp = AuthOtp(
            email=email,
            purpose=purpose,
            otp_hash=otp_hash,
            expires_at=expires_at,
            max_attempts=max_attempts,
        )
        self.db.add(otp)
        self.db.flush()
        return otp

    def revoke_active_otps(self, email: str, purpose: str) -> None:
        now = utcnow()
        otps = self.db.scalars(
            select(AuthOtp).where(
                AuthOtp.email == email,
                AuthOtp.purpose == purpose,
                AuthOtp.revoked_at.is_(None),
                AuthOtp.expires_at > now,
            )
        ).all()
        for otp in otps:
            otp.revoked_at = now
        self.db.flush()

    def get_active_otp(self, email: str, purpose: str) -> Optional[AuthOtp]:
        now = utcnow()
        return self.db.scalar(
            select(AuthOtp).where(
                AuthOtp.email == email,
                AuthOtp.purpose == purpose,
                AuthOtp.revoked_at.is_(None),
                AuthOtp.expires_at > now,
            ).order_by(AuthOtp.created_at.desc())
        )

    def increment_attempt(self, otp: AuthOtp) -> int:
        otp.attempt_count += 1
        self.db.flush()
        return otp.attempt_count

    def revoke_otp(self, otp: AuthOtp) -> None:
        otp.revoked_at = utcnow()
        self.db.flush()

    def get_otp_by_id(self, otp_id: str) -> Optional[AuthOtp]:
        return self.db.get(AuthOtp, otp_id)

    def get_last_otp(self, email: str, purpose: str) -> Optional[AuthOtp]:
        """Return the most recently created OTP record for email+purpose.

        Used to enforce resend cooldowns regardless of the latest record's
        revoked/expired state.
        """
        return self.db.scalar(
            select(AuthOtp)
            .where(AuthOtp.email == email, AuthOtp.purpose == purpose)
            .order_by(AuthOtp.created_at.desc())
        )

    def count_otps_issued(self, email: str, purpose: str, since: datetime) -> int:
        """Count OTP records created for email+purpose since a given time."""
        return self.db.scalar(
            select(func.count(AuthOtp.id)).where(
                AuthOtp.email == email,
                AuthOtp.purpose == purpose,
                AuthOtp.created_at >= since,
            )
        )

    # Refresh tokens
    def create_refresh_token(
        self, user_id: str, token_hash: str, expires_at: datetime,
        rotated_from: Optional[str] = None,
    ) -> AuthRefreshToken:
        token = AuthRefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            rotated_from=rotated_from,
        )
        self.db.add(token)
        self.db.flush()
        return token

    def get_refresh_token(self, token_hash: str) -> Optional[AuthRefreshToken]:
        return self.db.scalar(
            select(AuthRefreshToken).where(AuthRefreshToken.token_hash == token_hash)
        )

    def revoke_refresh_token(self, token: AuthRefreshToken) -> None:
        token.is_revoked = True
        token.revoked_at = utcnow()
        self.db.flush()

    def revoke_all_user_tokens(self, user_id: str) -> None:
        tokens = self.db.scalars(
            select(AuthRefreshToken).where(
                AuthRefreshToken.user_id == user_id,
                AuthRefreshToken.is_revoked.is_(False),
            )
        ).all()
        now = utcnow()
        for t in tokens:
            t.is_revoked = True
            t.revoked_at = now
        self.db.flush()
