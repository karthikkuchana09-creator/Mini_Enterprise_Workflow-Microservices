from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator

from app.core.constants import OtpPurpose


class _RegisterRequestBase(BaseModel):
    """Shared registration payload for Individual and Organization accounts.

    Note: the response of this flow never contains the OTP itself. The OTP is
    delivered by email only (the value is stored hashed server-side).
    """

    full_name: str = Field(
        min_length=1,
        max_length=255,
        description="User's display name.",
        examples=["Ada Lovelace"],
    )
    email: EmailStr = Field(
        description=(
            "Registration email. Individual accounts require a personal email "
            "domain; organization accounts require a business (non-personal) email."
        ),
        examples=["ada@example.com"],
    )
    password: str = Field(
        min_length=8,
        max_length=128,
        description="Account password (minimum 8 characters).",
        examples=["s3cure-PassW0rd"],
    )
    confirm_password: str = Field(
        min_length=8,
        max_length=128,
        description="Must exactly match `password`, otherwise a validation error is raised.",
        examples=["s3cure-PassW0rd"],
    )

    @model_validator(mode="after")
    def _passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("password and confirm_password do not match")
        return self


class IndividualRegisterRequest(_RegisterRequestBase):
    """Individual registration variant (discriminated by `account_type`)."""

    account_type: Literal["individual"] = Field(
        description=(
            "Discriminator selecting the Individual registration flow. "
            "Determines which response/flow branch is used."
        ),
        examples=["individual"],
    )


class OrganizationRegisterRequest(_RegisterRequestBase):
    """Organization / tenant registration variant (discriminated by `account_type`)."""

    organization_name: str = Field(
        min_length=1,
        max_length=255,
        description=(
            "Organization name. Creates a pending tenant whose admin account "
            "is the user registering here."
        ),
        examples=["Acme Inc"],
    )
    account_type: Literal["organization"] = Field(
        description=(
            "Discriminator selecting the Organization (tenant admin) "
            "registration flow."
        ),
        examples=["organization"],
    )


class RegistrationChallengeResponse(BaseModel):
    """Response after a successful registration start.

    The OTP code itself is NOT returned: it is emailed to the address in
    `email`. `expires_in` communicates the OTP lifetime. The `otp_token`
    cookie set by this call is required by `POST /auth/verify-otp`.
    """

    message: str = Field(
        description="Human-readable status message.",
        examples=["Registration started. Check your email for the OTP."],
    )
    email: str = Field(
        description="Email address the OTP was delivered to.",
        examples=["ada@example.com"],
    )
    expires_in: int = Field(
        description="OTP lifetime in seconds.",
        examples=[300],
    )

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "message": "Registration started. Check your email for the OTP.",
                    "email": "ada@example.com",
                    "expires_in": 300,
                }
            ]
        }
    )


class VerifyOtpRequest(BaseModel):
    """Body for OTP verification (registration / forgot-password)."""

    otp: str = Field(
        min_length=6,
        max_length=6,
        description="6-digit one-time password as received by email.",
        examples=["123456"],
    )


class RegisterIndividualRequest(BaseModel):
    """(Legacy) Individual registration payload used by `/auth/register/individual`."""

    email: EmailStr = Field(
        description="Registration email (personal domain).",
        examples=["ada@example.com"],
    )
    password: str = Field(
        min_length=8,
        max_length=128,
        description="Account password (minimum 8 characters).",
        examples=["s3cure-PassW0rd"],
    )
    full_name: str = Field(
        min_length=1,
        max_length=255,
        description="User's display name.",
        examples=["Ada Lovelace"],
    )


class RegisterTenantRequest(BaseModel):
    """(Legacy) Organization registration payload used by `/auth/register/tenant`."""

    email: EmailStr = Field(
        description="Admin account email (business domain).",
        examples=["boss@acme.com"],
    )
    password: str = Field(
        min_length=8,
        max_length=128,
        description="Account password (minimum 8 characters).",
        examples=["s3cure-PassW0rd"],
    )
    full_name: str = Field(
        min_length=1,
        max_length=255,
        description="Admin user's display name.",
        examples=["Boss"],
    )
    org_name: str = Field(
        min_length=1,
        max_length=255,
        description="Organization name.",
        examples=["Acme Inc"],
    )
    org_email: EmailStr = Field(
        description="Organization business email.",
        examples=["hello@acme.com"],
    )


class LoginRequest(BaseModel):
    """Body for `POST /auth/login`."""

    email: EmailStr = Field(
        description="Registered and verified email address.",
        examples=["ada@example.com"],
    )
    password: str = Field(
        description="Account password.",
        examples=["s3cure-PassW0rd"],
    )


class OtpVerifyRequest(BaseModel):
    """(Legacy) Body for `/auth/otp/verify` email activation."""

    email: EmailStr = Field(
        description="Email address the OTP was issued for.",
        examples=["ada@example.com"],
    )
    otp: str = Field(
        min_length=6,
        max_length=6,
        description="6-digit one-time password.",
        examples=["123456"],
    )
    purpose: OtpPurpose = Field(
        description=(
            "OTP purpose; must match the purpose used when the OTP was issued "
            "(e.g. `email_verify`)."
        ),
        examples=[OtpPurpose.EMAIL_VERIFY],
    )


class OtpResendRequest(BaseModel):
    """(Legacy) Body for `/auth/otp/resend`."""

    email: EmailStr = Field(
        description="Email address to re-send the OTP to.",
        examples=["ada@example.com"],
    )
    purpose: OtpPurpose = Field(
        description="OTP purpose to re-send.",
        examples=[OtpPurpose.EMAIL_VERIFY],
    )


class ForgotPasswordRequest(BaseModel):
    """Body for `POST /auth/forgot-password`."""

    email: EmailStr = Field(
        description=(
            "Account email to reset. The response is identical for unknown "
            "emails to prevent user enumeration."
        ),
        examples=["ada@example.com"],
    )


class ResetPasswordRequest(BaseModel):
    """Body for `POST /auth/reset-password`."""

    new_password: str = Field(
        min_length=8,
        max_length=128,
        description="New password (minimum 8 characters).",
        examples=["New-s3cure-PassW0rd"],
    )
    confirm_password: str = Field(
        min_length=8,
        max_length=128,
        description="Must exactly match `new_password`.",
        examples=["New-s3cure-PassW0rd"],
    )


class TokenResponse(BaseModel):
    access_token: str = Field(
        description="Access token. Example value is a placeholder - real JWTs are never shown.",
        examples=["<access-token>"],
    )
    token_type: str = "bearer"


class UserSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(description="Unique user identifier (UUID).", examples=["167b3a1c-..."])
    email: str = Field(description="User email address.", examples=["ada@example.com"])
    full_name: str = Field(description="Display name.", examples=["Ada Lovelace"])
    role: str = Field(
        description="Assigned role (individual / tenant_admin / tenant_user / super_admin).",
        examples=["individual"],
    )
    user_type: str = Field(
        description="Account type (individual / tenant_admin / tenant_user).",
        examples=["individual"],
    )
    status: str = Field(
        description="Account lifecycle status (pending / active / inactive).",
        examples=["active"],
    )
    tenant_id: Optional[str] = Field(
        default=None,
        description="Owning tenant id for organization accounts, else null.",
        examples=["33f2b9d0-..."],
    )


class AuthResponse(BaseModel):
    """Login / registration-completion / token-refresh response.

    - `access_token` is returned in the JSON body AND as an HttpOnly cookie
      (`access_token`) for request passthrough and cookie-based flows.
    - `refresh_token` is returned ONLY as an HttpOnly cookie (`refresh_token`);
      it is never included in the JSON body. It is required by
      `POST /auth/refresh-token` and `POST /auth/logout`.
    - No real token values are shown in API documentation examples.
    """

    access_token: str = Field(
        description=(
            "JWT for authenticated endpoints, sent as `Authorization: Bearer "
            "<token>`. Also set as the HttpOnly `access_token` cookie. Runtime "
            "value only - never shown in documentation examples."
        ),
        examples=["<access-token>"],
    )
    token_type: str = "bearer"
    user: UserSummary = Field(description="Authenticated user summary.")

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "access_token": "<access-token>",
                    "token_type": "bearer",
                    "user": {
                        "id": "167b3a1c-0000-4000-8000-000000000001",
                        "email": "ada@example.com",
                        "full_name": "Ada Lovelace",
                        "role": "individual",
                        "user_type": "individual",
                        "status": "active",
                        "tenant_id": None,
                    },
                }
            ]
        }
    )


class MessageResponse(BaseModel):
    """Generic success message returned by action endpoints."""

    message: str = Field(
        description="Human-readable result message.",
        examples=["Logged out."],
    )


class OtpVerifyResponse(BaseModel):
    message: str = Field(
        default="OTP verified successfully",
        description="Confirmation message.",
        examples=["OTP verified successfully"],
    )