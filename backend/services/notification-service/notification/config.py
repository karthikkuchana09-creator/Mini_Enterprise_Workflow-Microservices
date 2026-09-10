"""Notification Service configuration.

Reads values from environment variables.  In Docker the container provides
these via ``docker-compose.yml``.  For local testing the shared ``.env``
file is used.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class NotificationSettings(BaseSettings):
    APP_NAME: str = "ECWF Notification Service"
    SERVICE_MODE: str = "monolith"

    DATABASE_URL: str = "mysql+pymysql://notification_user:notification_password@mysql:3306/ecwf_notification_db"

    INTERNAL_API_KEY: str = "replace_with_secure_internal_api_key"

    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""

    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )


notification_settings = NotificationSettings()
