"""Tenant Service configuration.

Reads values from environment variables.  In Docker the container provides
these via ``docker-compose.yml``.  For local testing the shared ``.env``
file is used.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class TenantSettings(BaseSettings):
    APP_NAME: str = "ECWF Tenant Service"
    SERVICE_MODE: str = "monolith"

    DATABASE_URL: str = "mysql+pymysql://tenant_user:tenant_password@mysql:3306/ecwf_tenant_db"

    SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "ecwf-auth"

    INTERNAL_API_KEY: str = "replace_with_secure_internal_api_key"
    AUTH_SERVICE_URL: str = "http://localhost:8001"
    NOTIFICATION_SERVICE_URL: str = "http://localhost:8004"

    OTP_EXPIRE_MINUTES: int = Field(default=5, ge=1)
    OTP_MAX_ATTEMPTS: int = Field(default=3, ge=1)
    OTP_RESEND_COOLDOWN_SECONDS: int = Field(default=60, ge=0)
    OTP_RESEND_WINDOW_MINUTES: int = Field(default=10, ge=1)
    OTP_MAX_RESENDS: int = Field(default=5, ge=1)

    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )


tenant_settings = TenantSettings()
