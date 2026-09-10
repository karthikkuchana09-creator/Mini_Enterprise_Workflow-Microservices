class ECWFException(Exception):
    status_code = 500
    detail = "Internal server error"

    def __init__(self, message: str | None = None):
        self.message = message or self.detail
        super().__init__(self.message)


class NotFoundError(ECWFException):
    status_code = 404
    detail = "Resource not found"


class ConflictError(ECWFException):
    status_code = 409
    detail = "Resource conflict"


class UnauthorizedError(ECWFException):
    status_code = 401
    detail = "Unauthorized"


class ForbiddenError(ECWFException):
    status_code = 403
    detail = "Forbidden"


class BadRequestError(ECWFException):
    status_code = 400
    detail = "Bad request"


class ValidationError_(ECWFException):
    status_code = 422
    detail = "Validation error"


class InvalidCredentialsError(ECWFException):
    status_code = 401
    detail = "Invalid email or password"


class CredentialsInactiveError(ECWFException):
    status_code = 403
    detail = "Account is not active"


class OtpInvalidError(ECWFException):
    status_code = 400
    detail = "Invalid or expired OTP"


class OtpMaxAttemptsError(ECWFException):
    status_code = 429
    detail = "Too many failed OTP attempts"


class OtpResendTooSoonError(ECWFException):
    status_code = 429
    detail = "OTP resend requested too soon"


class OtpMaxResendError(ECWFException):
    status_code = 429
    detail = "Too many OTP resend attempts"


class EmailAlreadyExistsError(ConflictError):
    detail = "Email is already registered"
