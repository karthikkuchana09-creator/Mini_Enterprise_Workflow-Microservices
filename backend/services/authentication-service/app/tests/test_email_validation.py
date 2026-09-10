import pytest

from app.core.emails import (
    classify_email,
    extract_domain,
    is_personal_domain,
    normalize_email,
    validate_email_syntax,
    validate_individual_email,
    validate_organization_email,
)
from app.core.exceptions import ValidationError_

VALID_PERSONAL = [
    "user@gmail.com",
    "user@yahoo.com",
    "user@outlook.com",
    "user@hotmail.com",
    "user@icloud.com",
]


# ---------------------------------------------------------------------------
# 1. Valid individual emails (personal domains)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("email", VALID_PERSONAL)
def test_individual_valid_personal(email):
    assert validate_individual_email(email) == email


# ---------------------------------------------------------------------------
# 2. Invalid individual business emails
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("email", ["admin@company.com", "hr@organization.org", "support@company.in"])
def test_individual_rejects_business(email):
    with pytest.raises(ValidationError_):
        validate_individual_email(email)


# ---------------------------------------------------------------------------
# 3. Valid organization emails (business domains)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("email", ["admin@company.com", "hr@organization.org", "support@company.in"])
def test_organization_valid_business(email):
    assert validate_organization_email(email) == email


# ---------------------------------------------------------------------------
# 4. Invalid organization personal emails
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("email", VALID_PERSONAL)
def test_organization_rejects_personal(email):
    with pytest.raises(ValidationError_):
        validate_organization_email(email)


# ---------------------------------------------------------------------------
# 5. Uppercase emails are normalized to lowercase
# ---------------------------------------------------------------------------
def test_uppercase_email_normalized():
    assert validate_individual_email("User@Gmail.com") == "user@gmail.com"


def test_uppercase_org_email_normalized():
    assert validate_organization_email("ADMIN@Company.COM") == "admin@company.com"


# ---------------------------------------------------------------------------
# 6. Whitespace is trimmed
# ---------------------------------------------------------------------------
def test_whitespace_trimmed_individual():
    assert validate_individual_email("  user@gmail.com  ") == "user@gmail.com"


def test_whitespace_trimmed_org():
    assert validate_organization_email("  hr@organization.org  ") == "hr@organization.org"


# ---------------------------------------------------------------------------
# 7. Invalid email syntax rejected
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad",
    ["", "   ", "not-an-email", "user@", "@domain.com", "user@@gmail.com", "user.gmail.com"],
)
def test_invalid_syntax_rejected(bad):
    with pytest.raises(ValidationError_):
        validate_email_syntax(bad)


# ---------------------------------------------------------------------------
# 8. Duplicate emails detected via normalization
# ---------------------------------------------------------------------------
def test_duplicate_emails_normalize_identically():
    a = normalize_email("User@Gmail.com")
    b = normalize_email("  user@gmail.com    ")
    assert a == b


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------
def test_classify_email_personal():
    info = classify_email("User@Gmail.com")
    assert info["email"] == "user@gmail.com"
    assert info["domain"] == "gmail.com"
    assert info["is_personal"] is True


def test_classify_email_business():
    info = classify_email("admin@company.com")
    assert info["domain"] == "company.com"
    assert info["is_personal"] is False


def test_extract_domain():
    assert extract_domain("user@Outlook.com") == "outlook.com"


def test_is_personal_domain():
    assert is_personal_domain("GMAIL.COM") is True
    assert is_personal_domain("company.com") is False
