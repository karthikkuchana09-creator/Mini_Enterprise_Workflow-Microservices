"""Shared configuration loaded from environment variables.

Each microservice imports its service-specific subset; the values are
supplied by docker-compose or a local ``.env`` file.  In monolith/test
mode the auth-service ``app.core.config.settings`` object is used
instead.
"""

from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SharedSettings(BaseSettings):
    DATABASE_URL: str = ""

    # JWT (shared for token validation across services)
    SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "ecwf-auth"

    # Inter-service HTTP
    TENANT_SERVICE_URL: str = "http://localhost:8003"
    NOTIFICATION_SERVICE_URL: str = "http://localhost:8004"
    AUTH_SERVICE_URL: str = "http://localhost:8001"
    INTERNAL_API_KEY: str = "replace_with_secure_internal_api_key"

    # SMTP
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""

    # OTP
    OTP_EXPIRE_MINUTES: int = Field(default=5, ge=1)
    OTP_MAX_ATTEMPTS: int = Field(default=3, ge=1)
    OTP_RESEND_COOLDOWN_SECONDS: int = Field(default=60, ge=0)
    OTP_RESEND_WINDOW_MINUTES: int = Field(default=10, ge=1)
    OTP_MAX_RESENDS: int = Field(default=5, ge=1)

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )


shared_settings = SharedSettings()
