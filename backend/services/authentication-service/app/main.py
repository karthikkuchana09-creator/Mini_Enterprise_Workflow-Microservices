from fastapi import FastAPI
from sqlalchemy import text

from app.api.exception_handlers import register_exception_handlers
from app.api.auth_routes import router as auth_router
from app.api.internal_routes import router as internal_router
from app.api.user_routes import router as user_router
from app.core.config import settings
from app.db.session import engine
from app.middleware.cors import configure_cors
from tenant.api.v1.endpoints.tenant import router as tenant_router

OPENAPI_TAGS = [
    {
        "name": "authentication",
        "description": (
            "Account lifecycle: registration, email/OTP verification, resend "
            "OTP, login, logout and refresh-token rotation. "
            "Endpoints are public unless noted otherwise."
        ),
    },
    {
        "name": "password",
        "description": (
            "Password recovery: request a forgot-password OTP, verify it, and "
            "set a new password."
        ),
    },
    {
        "name": "users",
        "description": (
            "Authenticated profile endpoints. All requests require the "
            "`Authorization: Bearer <access-token>` header."
        ),
    },
    {
        "name": "tenants",
        "description": (
            "Organization endpoints. All requests require the "
            "`Authorization: Bearer <access-token>` header of an authorized "
            "tenant admin."
        ),
    },
]

app = FastAPI(
    title="ECWF API",
    version="1.0.0",
    description=(
        "API documentation for the **Enterprise Collaboration and Workflow "
        "Tool (ECWF)**.\n\n"
        "## Cookie-based authentication\n\n"
        "The authentication module issues three HttpOnly cookie types:\n\n"
        "- **`access_token`** - short-lived JWT authorizing authenticated "
        "endpoints. Set by `POST /auth/login`, `POST /auth/verify-otp`, and "
        "`POST /auth/refresh-token`. The same JWT is also returned in JSON "
        "response bodies for API-style usage (`Authorization: Bearer ...`).\n"
        "- **`refresh_token`** - long-lived JWT used only by "
        "`POST /auth/refresh-token` (token rotation) and `POST /auth/logout`. "
        "It is **never** exposed in JSON responses; it exists only as a cookie.\n"
        "- **`otp_token`** - short-lived OTP transaction token bound to a "
        "registration (or password-reset) challenge. Required by `POST "
        "/auth/verify-otp`, `POST /auth/resend-otp`, and `POST "
        "/auth/verify-forgot-otp`.\n\n"
        "## Security notes\n\n"
        "- One-time passwords (OTP) are delivered **by email only**. They are "
        "never returned in API responses and never stored in plain text.\n"
        "- Passwords are never stored or transmitted in plain text.\n"
        "- Access/refresh/OTP cookies are marked `HttpOnly`; the `Secure` flag "
        "is applied when configured for production.\n"
        "- Documentation examples never contain real tokens; placeholders like "
        "`<access-token>` are shown instead.\n\n"
        "All endpoints use `Bearer`-style access tokens via the "
        "`Authorization` header when authenticated; see the `users` and "
        "`tenants` tags."
    ),
    openapi_tags=OPENAPI_TAGS,
)

configure_cors(app)
register_exception_handlers(app)

app.include_router(auth_router)
app.include_router(user_router)
app.include_router(internal_router)
if settings.SERVICE_MODE != "microservices":
    # Modular monolith / tests: the tenant API runs inside this process.
    app.include_router(tenant_router)


@app.get("/")
def root():
    return {"message": "ECWF API is running"}


@app.get("/health")
def health_check():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {
            "status": "success",
            "database": "connected"
        }
    except Exception as e:
        return {
            "status": "failed",
            "database": "disconnected",
            "error": str(e)
        }
