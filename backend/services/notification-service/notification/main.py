"""Notification Service - standalone FastAPI application.

Runs as an independent microservice (uvicorn on port 8004) exposing the
internal email API consumed by auth-service and tenant-service over HTTP.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from notification.api.endpoints import router as email_router
from notification.config import notification_settings

app = FastAPI(
    title=notification_settings.APP_NAME,
    version="1.0.0",
    description=(
        "ECWF Notification Service. Emails (OTP, welcome, password-reset, "
        "invitation, login alerts) are delivered via SMTP when configured, "
        "otherwise logged for development. All endpoints require the "
        "`X-Internal-API-Key` header."
    ),
    openapi_tags=[
        {
            "name": "internal-emails",
            "description": (
                "Service-to-service email endpoints. Protected by the shared "
                "internal API key."
            ),
        }
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=notification_settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(email_router)


@app.get("/health")
def health_check():
    return {"status": "success", "service": "notification-service"}