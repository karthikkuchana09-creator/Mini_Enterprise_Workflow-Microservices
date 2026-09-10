from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "ECWF Tool"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Database
    DATABASE_URL: str = ""

    # Security / JWT
    SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "ecwf-auth"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15, ge=15, le=30)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, ge=7, le=30)

    # Email classification
    # Personal/free-mail domains allowed for Individual accounts and rejected for
    # Organization accounts. Configurable; not hard-coded.
    PERSONAL_EMAIL_DOMAINS: List[str] = [
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "icloud.com",
    ]

    # OTP
    OTP_EXPIRE_MINUTES: int = Field(default=5, ge=1)
    OTP_TOKEN_EXPIRE_MINUTES: int = Field(default=5, ge=1)
    OTP_MAX_ATTEMPTS: int = Field(default=3, ge=1)
    OTP_LENGTH: int = Field(default=6, ge=6, le=8)
    # Cooldown (seconds) that must elapse between OTP resends to prevent abuse.
    OTP_RESEND_COOLDOWN_SECONDS: int = Field(default=60, ge=0)
    # Maximum OTP issues per email+purpose within the resend window (abuse guard).
    OTP_MAX_RESENDS: int = Field(default=5, ge=1)
    OTP_RESEND_WINDOW_MINUTES: int = Field(default=10, ge=1)

    # Password policy
    PASSWORD_MIN_LENGTH: int = Field(default=8, ge=8)
    PASSWORD_MAX_LENGTH: int = Field(default=128, le=128)
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_NUMBER: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True

    # Cookies
    COOKIE_DOMAIN: str = ""
    COOKIE_SECURE: bool = True
    COOKIE_HTTPONLY: bool = True
    COOKIE_SAMESITE: str = "strict"
    COOKIE_PATH: str = "/"
    ACCESS_TOKEN_COOKIE_NAME: str = "access_token"
    REFRESH_TOKEN_COOKIE_NAME: str = "refresh_token"
    OTP_TOKEN_COOKIE_NAME: str = "otp_token"
    RESET_TOKEN_COOKIE_NAME: str = "reset_token"
    # Password-reset state validity in minutes (post-OTP-verification window).
    RESET_TOKEN_EXPIRE_MINUTES: int = Field(default=10, ge=1, le=30)

    # Email / Notifications
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""

    # Service mode & inter-service HTTP
    SERVICE_MODE: str = "monolith"
    TENANT_SERVICE_URL: str = "http://localhost:8003"
    NOTIFICATION_SERVICE_URL: str = "http://localhost:8004"
    INTERNAL_API_KEY: str = "replace_with_secure_internal_api_key"

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )

    @field_validator("JWT_ALGORITHM")
    @classmethod
    def _validate_jwt_algorithm(cls, v: str) -> str:
        if v not in ("HS256", "HS384", "HS512"):
            raise ValueError("JWT_ALGORITHM must be one of HS256, HS384, HS512")
        return v

    @field_validator("COOKIE_SAMESITE")
    @classmethod
    def _validate_samesite(cls, v: str) -> str:
        if v not in ("strict", "lax", "none"):
            raise ValueError("COOKIE_SAMESITE must be strict, lax, or none")
        return v


settings = Settings()
