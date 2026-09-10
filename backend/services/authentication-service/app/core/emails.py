"""Reusable email classification and validation for account registration.

Personal vs. business classification is driven by the configurable
PERSONAL_EMAIL_DOMAINS setting. Individual registration requires a personal
domain; Organization registration requires a business (non-personal) domain.
"""
from email_validator import EmailNotValidError, validate_email

from app.core.config import settings
from app.core.exceptions import ValidationError_


def normalize_email(email: str) -> str:
    """Trim surrounding whitespace and lowercase an email address."""
    return email.strip().lower()


def validate_email_syntax(email: str) -> str:
    """Validate email syntax and return a normalized (trimmed, lowercased) email.

    Raises ValidationError_ with a clear message on invalid input.
    """
    if not email or not email.strip():
        raise ValidationError_("Email is required")
    try:
        result = validate_email(email.strip(), check_deliverability=False)
    except EmailNotValidError as exc:
        raise ValidationError_(f"Invalid email format: {exc}") from exc
    return result.normalized.lower()


def extract_domain(email: str) -> str:
    """Safely extract the domain (case-insensitive) from a normalized email.

    Returns the lowercase domain. Raises ValidationError_ if no '@' is present.
    """
    normalized = email.strip().lower()
    if "@" not in normalized or normalized.count("@") != 1:
        raise ValidationError_("Invalid email address")
    domain = normalized.rsplit("@", 1)[1]
    if not domain or "." not in domain:
        raise ValidationError_("Invalid email domain")
    return domain


def is_personal_domain(domain: str) -> bool:
    """Return True if the domain is in the configured personal/free-email list."""
    configured = {d.strip().lower() for d in settings.PERSONAL_EMAIL_DOMAINS if d.strip()}
    return domain.strip().lower() in configured


def classify_email(email: str) -> dict:
    """Validate syntax and classify an email as personal or business.

    Returns a dict with the normalized email, extracted domain, and an
    `is_personal` flag. Raises ValidationError_ for invalid syntax.
    """
    normalized = validate_email_syntax(email)
    domain = extract_domain(normalized)
    return {
        "email": normalized,
        "domain": domain,
        "is_personal": is_personal_domain(domain),
    }


def validate_individual_email(email: str) -> str:
    """Validate an email for an Individual account.

    Only personal domains are allowed. Returns the normalized email on success,
    or raises ValidationError_ with a clear message.
    """
    info = classify_email(email)
    if not info["is_personal"]:
        raise ValidationError_(
            f"Only personal email domains are allowed for individual accounts. "
            f"'{info['domain']}' is not a supported personal domain."
        )
    return info["email"]


def validate_organization_email(email: str) -> str:
    """Validate a business/official email for an Organization account.

    Personal/free-mail domains are rejected; any other domain is treated as a
    valid business email. Returns the normalized email on success, or raises
    ValidationError_ with a clear message.
    """
    info = classify_email(email)
    if info["is_personal"]:
        raise ValidationError_(
            f"Personal email domains are not allowed for organization accounts. "
            f"'{info['domain']}' is a personal/free-mail domain."
        )
    return info["email"]
