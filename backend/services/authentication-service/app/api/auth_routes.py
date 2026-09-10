from typing import Annotated, Union

from fastapi import APIRouter, Cookie, Depends, Response
from pydantic import Field
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import InvalidCredentialsError, OtpInvalidError
from app.core.security import (
    get_cookie_params_with_domain,
    get_otp_token_cookie_clear_params,
    get_otp_token_cookie_params,
)
from app.db.session import get_db
from app.schemas.auth import (
    AuthResponse,
    ForgotPasswordRequest,
    IndividualRegisterRequest,
    LoginRequest,
    MessageResponse,
    OrganizationRegisterRequest,
    OtpResendRequest,
    OtpVerifyRequest,
    RegisterIndividualRequest,
    RegisterTenantRequest,
    RegistrationChallengeResponse,
    ResetPasswordRequest,
    TokenResponse,
    VerifyOtpRequest,
)
from app.schemas.user import UserBase
from app.services.auth_service import AuthService
from tenant.schemas.tenant import InvitationAcceptRequest

router = APIRouter(prefix="/auth", tags=["authentication"])

ACCESS_COOKIE = settings.ACCESS_TOKEN_COOKIE_NAME
REFRESH_COOKIE = settings.REFRESH_TOKEN_COOKIE_NAME
OTP_COOKIE = settings.OTP_TOKEN_COOKIE_NAME
RESET_COOKIE = settings.RESET_TOKEN_COOKIE_NAME


def _set_access_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=ACCESS_COOKIE,
        value=token,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        **get_cookie_params_with_domain(),
    )


def _clear_access_cookie(response: Response) -> None:
    response.delete_cookie(
        key=ACCESS_COOKIE,
        **get_cookie_params_with_domain(),
    )


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=token,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        **get_cookie_params_with_domain(),
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=REFRESH_COOKIE,
        **get_cookie_params_with_domain(),
    )


def _set_otp_token_cookie(response: Response, token: str) -> None:
    response.set_cookie(key=OTP_COOKIE, value=token, **get_otp_token_cookie_params())


def _clear_otp_token_cookie(response: Response) -> None:
    response.delete_cookie(key=OTP_COOKIE, **get_otp_token_cookie_clear_params())


def _set_reset_token_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=RESET_COOKIE,
        value=token,
        max_age=settings.RESET_TOKEN_EXPIRE_MINUTES * 60,
        **get_cookie_params_with_domain(),
    )


def _clear_reset_token_cookie(response: Response) -> None:
    response.delete_cookie(
        key=RESET_COOKIE,
        **get_cookie_params_with_domain(),
    )


RegisterPayload = Annotated[
    Union[IndividualRegisterRequest, OrganizationRegisterRequest],
    Field(discriminator="account_type"),
]


@router.post(
    "/register",
    response_model=RegistrationChallengeResponse,
    status_code=201,
    summary="Register an individual or organization",
    response_description="Registration challenge created; OTP emailed",
    description=(
        "Public endpoint (no authentication required).\n\n"
        "Starts registration for an **Individual** (`account_type=individual`) "
        "or **Organization / tenant admin** (`account_type=organization`) "
        "account. Validates the email and password, persists a pending "
        "(inactive) account, issues a 6-digit OTP that is **emailed to the "
        "user** - never returned in the response - and sets the "
        "**`otp_token`** HttpOnly cookie.\n\n"
        "### Request fields\n"
        "- `account_type` *(required)* - `individual` or `organization`.\n"
        "- `full_name`, `email`, `password`, `confirm_password` *(required)*.\n"
        "- `organization_name` *(required when `account_type=organization`)*.\n\n"
        "### Authentication requirements\n"
        "None - public. The issued OTP is delivered by email only.\n\n"
        "### Cookie requirements\n"
        "Sets the `otp_token` cookie, required by `POST /auth/verify-otp`.\n\n"
        "### Status codes\n"
        "- **201** - registration challenge created, OTP emailed.\n"
        "- **409** - email already registered.\n"
        "- **422** - validation error: password mismatch, invalid email or password.\n\n"
        "### Example request\n"
        "```json\n"
        '{"account_type": "individual", "full_name": "Ada Lovelace", '
        '"email": "ada@example.com", "password": "s3cure-PassW0rd", '
        '"confirm_password": "s3cure-PassW0rd"}\n'
        "```\n\n"
        "### Example response (201)\n"
        "```json\n"
        '{"message": "Registration started. Check your email for the OTP.", '
        '"email": "ada@example.com", "expires_in": 300}\n'
        "```\n"
    ),
    responses={
        409: {
            "description": "Conflict: an account with this email already exists."
        },
        422: {
            "description": (
                "Validation Error: password/confirm_password mismatch, or "
                "invalid email/password/field constraints."
            ),
        },
    },
)
def register(
    payload: RegisterPayload,
    response: Response,
    db: Session = Depends(get_db),
):
    auth_service = AuthService(db)
    if isinstance(payload, IndividualRegisterRequest):
        result = auth_service.begin_individual_registration(
            full_name=payload.full_name,
            email=payload.email,
            password=payload.password,
            confirm_password=payload.confirm_password,
        )
    else:
        result = auth_service.begin_organization_registration(
            full_name=payload.full_name,
            email=payload.email,
            password=payload.password,
            confirm_password=payload.confirm_password,
            org_name=payload.organization_name,
        )
    _set_otp_token_cookie(response, result["otp_token"])
    return RegistrationChallengeResponse(
        message="Registration started. Check your email for the OTP.",
        email=result["email"],
        expires_in=result["expires_in"],
    )


@router.post(
    "/verify-otp",
    response_model=AuthResponse,
    summary="Verify the registration OTP and activate the account",
    response_description="Account activated; access + refresh tokens issued",
    description=(
        "Public endpoint (no authentication required).\n\n"
        "Completes a registration started by `POST /auth/register`. Validates "
        "the submitted 6-digit OTP against the challenge bound to the "
        "**`otp_token`** cookie, activates the pending account "
        "(Individual or Organization + tenant admin), and issues tokens.\n\n"
        "### Request fields\n"
        "- `otp` *(required)* - 6-digit code received by email.\n\n"
        "### Authentication requirements\n"
        "None - the caller proves email ownership by presenting the "
        "`otp_token` cookie plus the correct OTP.\n\n"
        "### Cookie requirements\n"
        "- **Required input:** `otp_token` cookie (set by "
        "`POST /auth/register`; the cookie's transaction must match the "
        "verified OTP, so a stale/value-mismatched cookie is rejected).\n"
        "- **Output:** sets `access_token` and `refresh_token` HttpOnly "
        "cookies. `refresh_token` is cookie-only (never in JSON); "
        "`access_token` also appears in the JSON body.\n\n"
        "### Status codes\n"
        "- **200** - verified and activated; tokens issued.\n"
        "- **400** - missing/invalid/expired `otp_token` cookie, wrong OTP, "
        "or cookie does not match the verified OTP transaction.\n"
        "- **429** - too many failed OTP attempts (temporary lockout).\n"
        "- **422** - validation error (malformed OTP).\n\n"
        "### Example request\n"
        "```json\n"
        '{"otp": "123456"}\n'
        "```\n\n"
        "### Example response (200)\n"
        "```json\n"
        '{"access_token": "<access-token>", "token_type": "bearer", "user": {'
        '"id": "167b3a1c-0000-4000-8000-000000000001", "email": '
        '"ada@example.com", "full_name": "Ada Lovelace", "role": "individual", '
        '"user_type": "individual", "status": "active", "tenant_id": null}}\n'
        "```\n"
        "Real access tokens are never shown in documentation examples.\n"
    ),
    responses={
        400: {
            "description": (
                "Bad request: missing/invalid/expired otp_token cookie, "
                "incorrect OTP, or OTP transaction mismatch."
            ),
        },
        429: {
            "description": "Too many failed OTP attempts; try again shortly."
        },
        422: {
            "description": "Validation Error: `otp` must be exactly 6 characters."
        },
    },
)
def verify_otp(
    payload: VerifyOtpRequest,
    response: Response,
    otp_token: str | None = Cookie(
        default=None,
        alias=OTP_COOKIE,
        description="HttpOnly `otp_token` cookie issued by /auth/register.",
    ),
    db: Session = Depends(get_db),
):
    if not otp_token:
        raise OtpInvalidError()
    result = AuthService(db).complete_registration(
        otp=payload.otp, otp_token=otp_token
    )
    _clear_otp_token_cookie(response)
    _set_refresh_cookie(response, result["refresh_token"])
    _set_access_cookie(response, result["access_token"])
    return AuthResponse(access_token=result["access_token"], user=UserBase(**result["user"]))


@router.post(
    "/register/individual",
    response_model=MessageResponse,
    status_code=201,
    summary="[Legacy] Register an individual (email-verify flow)",
    response_description="Registration started; OTP emailed",
    description=(
        "Legacy alternative to `POST /auth/register` (individual). Creates a "
        "pending account, emails an OTP, and expects `POST /auth/otp/verify` "
        "to activate it. No cookies are set. Prefer `POST /auth/register`.\n\n"
        "### Request fields\n"
        "- `email`, `password`, `full_name` *(required)*.\n\n"
        "### Authentication requirements\n"
        "None - public.\n\n"
        "### Status codes\n"
        "- **201** - registration started (OTP emailed).\n"
        "- **409** - email already registered.\n"
        "- **422** - validation error.\n"
    ),
    responses={
        409: {"description": "Conflict: email already registered."},
        422: {"description": "Validation Error: invalid email/password."},
    },
)
def register_individual(
    payload: RegisterIndividualRequest,
    db: Session = Depends(get_db),
):
    AuthService(db).register_individual(
        email=payload.email, password=payload.password, full_name=payload.full_name
    )
    return MessageResponse(message="Registration started. Check your email for the OTP.")


@router.post(
    "/register/tenant",
    response_model=MessageResponse,
    status_code=201,
    summary="[Legacy] Register an organization (email-verify flow)",
    response_description="Registration started; OTP emailed",
    description=(
        "Legacy alternative to `POST /auth/register` (organization). Creates a "
        "pending tenant + admin, emails an OTP, and expects "
        "`POST /auth/otp/verify` to activate it. Prefer `POST /auth/register`.\n\n"
        "### Request fields\n"
        "- `email`, `password`, `full_name`, `org_name`, `org_email` "
        "*(all required)*.\n\n"
        "### Authentication requirements\n"
        "None - public.\n\n"
        "### Status codes\n"
        "- **201** - registration started (OTP emailed).\n"
        "- **409** - email or organization already registered.\n"
        "- **422** - validation error.\n"
    ),
    responses={
        409: {
            "description": (
                "Conflict: admin email or organization email already registered."
            )
        },
        422: {"description": "Validation Error: invalid fields."},
    },
)
def register_tenant(
    payload: RegisterTenantRequest,
    db: Session = Depends(get_db),
):
    AuthService(db).register_tenant(
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
        org_name=payload.org_name,
        org_email=payload.org_email,
    )
    return MessageResponse(message="Tenant registration started. Check your email for the OTP.")


@router.post(
    "/otp/verify",
    response_model=AuthResponse,
    summary="[Legacy] Verify OTP by email address",
    response_description="Account activated; access + refresh tokens issued",
    description=(
        "Legacy endpoint that verifies an OTP given the email + purpose in the "
        "body (no otp_token cookie). Used together with "
        "`POST /auth/register/individual` and `POST /auth/register/tenant`. "
        "Prefer `POST /auth/verify-otp`.\n\n"
        "### Request fields\n"
        "- `email` *(required)* - the registered email.\n"
        "- `otp` *(required)* - 6-digit code.\n"
        "- `purpose` *(required)* - the OTP purpose the code was issued for.\n\n"
        "### Authentication requirements\n"
        "None - public.\n\n"
        "### Cookie requirements\n"
        "Sets `access_token` and `refresh_token` HttpOnly cookies on success.\n\n"
        "### Status codes\n"
        "- **200** - verified and activated.\n"
        "- **400** - invalid/expired OTP.\n"
        "- **429** - too many failed attempts.\n"
        "- **422** - validation error.\n"
    ),
    responses={
        400: {"description": "Bad request: invalid or expired OTP."},
        429: {"description": "Too many failed OTP attempts."},
        422: {"description": "Validation Error: invalid fields."},
    },
)
def verify_email_otp(
    payload: OtpVerifyRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    result = AuthService(db).complete_email_verification(
        email=payload.email, otp=payload.otp
    )
    _set_refresh_cookie(response, result["refresh_token"])
    _set_access_cookie(response, result["access_token"])
    return AuthResponse(access_token=result["access_token"], user=UserBase(**result["user"]))


@router.post(
    "/otp/resend",
    response_model=MessageResponse,
    summary="[Legacy] Resend OTP by email address",
    response_description="New OTP issued and emailed",
    description=(
        "Legacy endpoint that issues a fresh OTP for the given email + purpose "
        "(no otp_token cookie). Subject to the same cooldown "
        "(`OTP_RESEND_COOLDOWN_SECONDS`) and rate cap "
        "(`OTP_MAX_RESENDS`) as `POST /auth/resend-otp`. "
        "Prefer `POST /auth/resend-otp`.\n\n"
        "### Request fields\n"
        "- `email` *(required)* - recipient email.\n"
        "- `purpose` *(required)* - OTP purpose to re-issue.\n\n"
        "### Authentication requirements\n"
        "None - public.\n\n"
        "### Status codes\n"
        "- **200** - new OTP emailed.\n"
        "- **429** - resend cooldown or daily/resend cap exceeded.\n"
        "- **422** - validation error.\n"
    ),
    responses={
        429: {
            "description": (
                "Too many resends: cooldown window or resend cap exceeded."
            )
        },
        422: {"description": "Validation Error: invalid fields."},
    },
)
def resend_otp(
    payload: OtpResendRequest,
    db: Session = Depends(get_db),
):
    AuthService(db).resend_otp(email=payload.email, purpose=payload.purpose)
    return MessageResponse(message="OTP sent.")


@router.post(
    "/resend-otp",
    response_model=MessageResponse,
    summary="Resend OTP for the active challenge (cookie-based)",
    response_description="New OTP issued, emailed, and bound to a fresh cookie",
    description=(
        "Public endpoint (no authentication required).\n\n"
        "Re-issues the OTP for the challenge bound to the **`otp_token`** "
        "cookie (registration, forgot-password, etc.). The previous OTP is "
        "invalidated, a fresh code is emailed, and the cookie is replaced with "
        "a new OTP transaction token. The OTP value is **never** returned in "
        "the response.\n\n"
        "### Request fields\n"
        "None - the recipient email and purpose are derived from the cookie.\n\n"
        "### Authentication requirements\n"
        "None - the cookie proves the caller controls the challenge's email.\n\n"
        "### Cookie requirements\n"
        "- **Required input:** `otp_token` cookie (any verified "
        "challenge).\n"
        "- **Output:** replaces the `otp_token` cookie.\n\n"
        "### Status codes\n"
        "- **200** - new OTP emailed and cookie refreshed.\n"
        "- **400** - missing, expired, or invalid `otp_token` cookie.\n"
        "- **429** - cooldown not elapsed, or resend cap "
        "(`OTP_MAX_RESENDS`) exceeded.\n\n"
        "### Example response (200)\n"
        "```json\n"
        '{"message": "A new OTP has been sent."}\n'
        "```\n"
    ),
    responses={
        400: {
            "description": (
                "Bad request: missing, expired, or malformed otp_token cookie."
            )
        },
        429: {
            "description": (
                "Too many resends: cooldown window or resend cap exceeded."
            )
        },
    },
)
def resend_otp_from_cookie(
    response: Response,
    otp_token: str | None = Cookie(
        default=None,
        alias=OTP_COOKIE,
        description=(
            "HttpOnly `otp_token` cookie carrying the active OTP challenge."
        ),
    ),
    db: Session = Depends(get_db),
):
    if not otp_token:
        raise OtpInvalidError()
    new_otp_token = AuthService(db).resend_otp_from_cookie(otp_token=otp_token)
    _set_otp_token_cookie(response, new_otp_token)
    return MessageResponse(message="A new OTP has been sent.")


@router.post(
    "/login",
    response_model=AuthResponse,
    summary="Log in and obtain access + refresh tokens",
    response_description="Authenticated; access + refresh tokens issued",
    description=(
        "Public endpoint (no authentication required).\n\n"
        "Authenticates an active, email-verified account and issues a pair of "
        "tokens. A best-effort security notification email is sent on "
        "successful login; a notification failure never blocks login.\n\n"
        "### Request fields\n"
        "- `email` *(required)* - registered, verified email.\n"
        "- `password` *(required)* - account password.\n\n"
        "### Authentication requirements\n"
        "None on input - the credentials in the body are the authentication.\n\n"
        "### Cookie requirements\n"
        "- **Output:** sets `access_token` and `refresh_token` HttpOnly "
        "cookies. `refresh_token` is cookie-only; `access_token` also returned "
        "in JSON.\n\n"
        "### Status codes\n"
        "- **200** - authenticated; tokens issued.\n"
        "- **401** - invalid email/password.\n"
        "- **403** - account inactive, pending, or email not verified.\n"
        "- **422** - validation error (missing/invalid fields).\n\n"
        "### Example request\n"
        "```json\n"
        '{"email": "ada@example.com", "password": "s3cure-PassW0rd"}\n'
        "```\n\n"
        "### Example response (200)\n"
        "```json\n"
        '{"access_token": "<access-token>", "token_type": "bearer", "user": {'
        '"id": "167b3a1c-0000-4000-8000-000000000001", "email": '
        '"ada@example.com", "full_name": "Ada Lovelace", "role": "individual", '
        '"user_type": "individual", "status": "active", "tenant_id": null}}\n'
        "```\n"
        "Real tokens are never shown in documentation examples.\n"
    ),
    responses={
        401: {"description": "Unauthorized: unknown email or wrong password."},
        403: {
            "description": (
                "Forbidden: account inactive, pending, or email not verified."
            )
        },
        422: {"description": "Validation Error: missing email/password."},
    },
)
def login(
    payload: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    result = AuthService(db).login(email=payload.email, password=payload.password)
    _set_refresh_cookie(response, result["refresh_token"])
    _set_access_cookie(response, result["access_token"])
    return AuthResponse(access_token=result["access_token"], user=UserBase(**result["user"]))


@router.post(
    "/refresh-token",
    response_model=AuthResponse,
    summary="Refresh the access token (token rotation)",
    response_description="Pair rotated; new access + refresh tokens issued",
    description=(
        "Rotates the session: the presented refresh token is revoked, a new "
        "refresh token + access token are issued, and the `refresh_token` "
        "cookie is replaced.\n\n"
        "### Request fields\n"
        "None - the refresh token is read from the cookie.\n\n"
        "### Authentication requirements\n"
        "The valid, unexpired `refresh_token` cookie **is** the credential.\n\n"
        "### Cookie requirements\n"
        "- **Required input:** `refresh_token` HttpOnly cookie.\n"
        "- **Output:** replaces the `refresh_token` cookie; sets a fresh "
        "`access_token` cookie.\n\n"
        "### Status codes\n"
        "- **200** - rotation succeeded; new token pair issued.\n"
        "- **401** - missing, expired, revoked, or malformed refresh token "
        "(reuse of a rotated token is rejected).\n"
        "- **403** - user account no longer active.\n\n"
        "### Example response (200)\n"
        "```json\n"
        '{"access_token": "<access-token>", "token_type": "bearer", "user": {'
        '"id": "167b3a1c-0000-4000-8000-000000000001", "email": '
        '"ada@example.com", "full_name": "Ada Lovelace", "role": "individual", '
        '"user_type": "individual", "status": "active", "tenant_id": null}}\n'
        "```\n"
    ),
    responses={
        401: {
            "description": (
                "Unauthorized: missing/expired/revoked refresh token, or reuse "
                "of a rotated token."
            )
        },
        403: {"description": "Forbidden: user account inactive."},
    },
)
@router.post(
    "/refresh",
    response_model=AuthResponse,
    summary="[Legacy alias] Refresh the access token",
    response_description="Pair rotated; new access + refresh tokens issued",
    description=(
        "Legacy alias of `POST /auth/refresh-token` with identical semantics "
        "and cookie requirements. Prefer `/auth/refresh-token`."
    ),
)
def refresh(
    response: Response,
    refresh_token: str | None = Cookie(
        default=None,
        alias=REFRESH_COOKIE,
        description="HttpOnly `refresh_token` cookie issued at login/refresh.",
    ),
    db: Session = Depends(get_db),
):
    if not refresh_token:
        raise InvalidCredentialsError()
    result = AuthService(db).refresh(refresh_token=refresh_token)
    _set_refresh_cookie(response, result["refresh_token"])
    _set_access_cookie(response, result["access_token"])
    return AuthResponse(access_token=result["access_token"], user=UserBase(**result["user"]))


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Log out and revoke the session",
    response_description="Session revoked; cookies cleared",
    description=(
        "Revokes the refresh token(s) of the presented session and clears the "
        "`refresh_token`, `access_token`, and `otp_token` cookies. "
        "Idempotent: succeeds silently even when the cookie is absent, "
        "invalid, or already revoked.\n\n"
        "### Request fields\n"
        "None.\n\n"
        "### Authentication requirements\n"
        "Optional - presenting a valid `refresh_token` cookie revokes that "
        "session server-side; an absent/invalid cookie still returns 200.\n\n"
        "### Cookie requirements\n"
        "- **Optional input:** `refresh_token` cookie.\n"
        "- **Output:** clears `refresh_token`, `access_token`, and "
        "`otp_token` cookies.\n\n"
        "### Status codes\n"
        "- **200** - logged out (idempotent).\n\n"
        "### Example response (200)\n"
        "```json\n"
        '{"message": "Logged out."}\n'
        "```\n"
    ),
)
def logout(
    response: Response,
    refresh_token: str | None = Cookie(
        default=None,
        alias=REFRESH_COOKIE,
        description=(
            "Optional HttpOnly `refresh_token` cookie identifying the session "
            "to revoke."
        ),
    ),
    db: Session = Depends(get_db),
):
    AuthService(db).logout(refresh_token=refresh_token)
    _clear_refresh_cookie(response)
    _clear_access_cookie(response)
    _clear_otp_token_cookie(response)
    return MessageResponse(message="Logged out.")


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    tags=["password"],
    summary="Request a password-reset OTP",
    response_description="Reset OTP emailed (for registered emails)",
    description=(
        "Public endpoint (no authentication required).\n\n"
        "Issues a `forgot_password` OTP, emails it, and sets the "
        "**`otp_token`** cookie bound to that challenge. For unknown "
        "emails the response is **identical** (no OTP, no cookie) to prevent "
        "user enumeration.\n\n"
        "### Request fields\n"
        "- `email` *(required)* - the account email.\n\n"
        "### Authentication requirements\n"
        "None - public.\n\n"
        "### Cookie requirements\n"
        "**Output (registered email):** sets `otp_token` cookie, required "
        "by `POST /auth/verify-forgot-otp`.\n\n"
        "### Status codes\n"
        "- **200** - always (even for unknown emails).\n"
        "- **422** - validation error (invalid email).\n\n"
        "### Example request\n"
        "```json\n"
        '{"email": "ada@example.com"}\n'
        "```\n\n"
        "### Example response (200)\n"
        "```json\n"
        '{"message": "If the email exists, a reset OTP has been sent."}\n'
        "```\n"
    ),
    responses={
        422: {"description": "Validation Error: invalid email."},
    },
)
def forgot_password(
    payload: ForgotPasswordRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    otp_token = AuthService(db).forgot_password(email=payload.email)
    if otp_token:
        _set_otp_token_cookie(response, otp_token)
    return MessageResponse(message="If the email exists, a reset OTP has been sent.")


@router.post(
    "/verify-forgot-otp",
    response_model=MessageResponse,
    tags=["password"],
    summary="Verify the password-reset OTP",
    response_description="Reset OTP verified; reset state cookie issued",
    description=(
        "Public endpoint (no authentication required) that completes the "
        "forgot-password OTP step.\n\n"
        "Validates the `forgot_password` OTP bound to the **`otp_token`** "
        "cookie, then exchanges it for a short-lived **`reset_token`** cookie "
        "(`RESET_TOKEN_EXPIRE_MINUTES`, default 10 minutes) that authorizes "
        "`POST /auth/reset-password`. The `otp_token` cookie is cleared.\n\n"
        "### Request fields\n"
        "- `otp` *(required)* - 6-digit reset code received by email.\n\n"
        "### Authentication requirements\n"
        "None - the cookie + correct OTP prove email ownership.\n\n"
        "### Cookie requirements\n"
        "- **Required input:** `otp_token` cookie (purpose must be "
        "`forgot_password`).\n"
        "- **Output:** clears `otp_token`, sets `reset_token` cookie.\n\n"
        "### Status codes\n"
        "- **200** - verified; reset_token cookie issued.\n"
        "- **400** - missing/invalid/expired cookie, wrong OTP, or OTP "
        "transaction mismatch.\n"
        "- **429** - too many failed OTP attempts.\n"
        "- **422** - validation error.\n\n"
        "### Example request\n"
        "```json\n"
        '{"otp": "123456"}\n'
        "```\n\n"
        "### Example response (200)\n"
        "```json\n"
        '{"message": "OTP verified. You can now reset your password."}\n'
        "```\n"
    ),
    responses={
        400: {
            "description": (
                "Bad request: missing/invalid/expired cookie, wrong OTP, or "
                "transaction mismatch."
            )
        },
        429: {"description": "Too many failed OTP attempts."},
        422: {"description": "Validation Error: `otp` must be 6 characters."},
    },
)
def verify_forgot_otp(
    payload: VerifyOtpRequest,
    response: Response,
    otp_token: str | None = Cookie(
        default=None,
        alias=OTP_COOKIE,
        description=(
            "HttpOnly `otp_token` cookie issued by /auth/forgot-password."
        ),
    ),
    db: Session = Depends(get_db),
):
    if not otp_token:
        raise OtpInvalidError()
    reset_token = AuthService(db).verify_forgot_otp(
        otp_token=otp_token, otp=payload.otp
    )
    _clear_otp_token_cookie(response)
    _set_reset_token_cookie(response, reset_token)
    return MessageResponse(message="OTP verified. You can now reset your password.")


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    tags=["password"],
    summary="Set a new password",
    response_description="Password changed; session revoked; cookies cleared",
    description=(
        "Public endpoint (no authentication required) that applies the new "
        "password.\n\n"
        "Requires the **`reset_token`** cookie issued by "
        "`POST /auth/verify-forgot-otp`. On success the password is hashed and "
        "replaced, all active forgot-password OTPs and refresh tokens are "
        "revoked, and the `reset_token` + `otp_token` cookies are cleared. "
        "The password is **never** returned or logged.\n\n"
        "### Request fields\n"
        "- `new_password` *(required)* - new password (min 8 chars).\n"
        "- `confirm_password` *(required)* - must match `new_password`.\n\n"
        "### Authentication requirements\n"
        "The `reset_token` cookie is the proof of a completed OTP step.\n\n"
        "### Cookie requirements\n"
        "- **Required input:** `reset_token` cookie (purpose "
        "`password_reset`).\n"
        "- **Output:** clears `reset_token` and `otp_token` cookies.\n\n"
        "### Status codes\n"
        "- **200** - password changed; all sessions revoked.\n"
        "- **400** - missing, expired, or invalid `reset_token` cookie.\n"
        "- **422** - validation error: password mismatch or weak password.\n\n"
        "### Example request\n"
        "```json\n"
        '{"new_password": "New-s3cure-PassW0rd", '
        '"confirm_password": "New-s3cure-PassW0rd"}\n'
        "```\n\n"
        "### Example response (200)\n"
        "```json\n"
        '{"message": "Password reset successfully."}\n'
        "```\n"
    ),
    responses={
        400: {
            "description": "Bad request: missing/expired/invalid reset_token cookie."
        },
        422: {
            "description": (
                "Validation Error: password mismatch, weak password, or "
                "invalid fields."
            )
        },
    },
)
def reset_password(
    payload: ResetPasswordRequest,
    response: Response,
    reset_token: str | None = Cookie(
        default=None,
        alias=RESET_COOKIE,
        description="HttpOnly `reset_token` cookie set by /auth/verify-forgot-otp.",
    ),
    db: Session = Depends(get_db),
):
    if not reset_token:
        raise OtpInvalidError()
    AuthService(db).reset_password(
        reset_token=reset_token,
        new_password=payload.new_password,
        confirm_password=payload.confirm_password,
    )
    _clear_reset_token_cookie(response)
    _clear_otp_token_cookie(response)
    return MessageResponse(message="Password reset successfully.")


@router.post(
    "/accept-invitation",
    response_model=MessageResponse,
    status_code=201,
    summary="Accept a tenant invitation",
    response_description="Invitation accepted; activation OTP emailed",
    description=(
        "Public endpoint (no authentication required).\n\n"
        "Accepts a tenant invitation using the one-time token from the invite "
        "email, creates the pending tenant user/admin account, and emails an "
        "activation OTP. Succeeds only if the invitation is unused and "
        "unexpired and no account exists for that email yet. Actual activation "
        "happens via `POST /auth/otp/verify`.\n\n"
        "### Request fields\n"
        "- `token` *(required)* - one-time invitation token from the invite "
        "email.\n"
        "- `full_name` *(required)* - the teammate's display name.\n"
        "- `password` *(required)* - account password (min 8 chars).\n\n"
        "### Authentication requirements\n"
        "None - the invite token is the credential.\n\n"
        "### Status codes\n"
        "- **201** - invitation accepted; OTP emailed.\n"
        "- **400** - invitation expired (or missing fields).\n"
        "- **404** - invitation token unknown/already used.\n"
        "- **409** - invitation already accepted, or an account already exists "
        "for the email.\n"
        "- **422** - validation error.\n\n"
        "### Example request\n"
        "```json\n"
        '{"token": "<invite-token>", "full_name": "Grace Hopper", '
        '"password": "s3cure-PassW0rd"}\n'
        "```\n"
        "Invite tokens are one-time values delivered by email; examples show "
        "placeholders only.\n"
    ),
    responses={
        400: {"description": "Bad request: invitation has expired."},
        404: {"description": "Not found: unknown or already-used invitation token."},
        409: {
            "description": (
                "Conflict: invitation already accepted, or account already "
                "registered for the invited email."
            )
        },
        422: {"description": "Validation Error: invalid fields."},
    },
)
def accept_invitation(
    payload: InvitationAcceptRequest,
    db: Session = Depends(get_db),
):
    AuthService(db).accept_invitation(
        token=payload.token,
        full_name=payload.full_name,
        password=payload.password,
    )
    return MessageResponse(message="Invitation accepted. Check your email for the OTP to activate your account.")
