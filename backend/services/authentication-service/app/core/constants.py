from enum import Enum


class UserType(str, Enum):
    INDIVIDUAL = "individual"
    TENANT_ADMIN = "tenant_admin"
    TENANT_USER = "tenant_user"


class UserRole(str, Enum):
    INDIVIDUAL = "individual"
    TENANT_USER = "tenant_user"
    TENANT_ADMIN = "tenant_admin"
    SUPER_ADMIN = "super_admin"


class UserStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"


class TenantStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"


class OtpPurpose(str, Enum):
    # Canonical purposes
    REGISTRATION = "registration"
    FORGOT_PASSWORD = "forgot_password"
    # Backward-compatible aliases
    EMAIL_VERIFY = "email_verify"
    PASSWORD_RESET = "password_reset"


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    OTP = "otp"
