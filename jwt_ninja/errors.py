from typing import Literal


class JWTError(Exception):
    """Base class for JWT exceptions."""

    def __init__(
        self,
        error_code: str,
        error_friendly: str,
        http_status_code: int,
        **kwargs,
    ):
        self.error_code = error_code
        self.error_friendly = error_friendly
        self.http_status_code = http_status_code


class JWTExpiredError(JWTError):
    """Exception raised when a JWT token has expired."""

    def __init__(self, **kwargs):
        super().__init__(
            error_code="expired_token",
            error_friendly="Token has expired",
            http_status_code=401,
            **kwargs,
        )


class JWTInvalidTokenError(JWTError):
    """Exception raised when a JWT token is invalid."""

    def __init__(self, **kwargs):
        super().__init__(
            error_code="invalid_token",
            error_friendly="Token is invalid",
            http_status_code=401,
            **kwargs,
        )


class JWTInvalidPayloadFormat(JWTError):
    """Exception raised when the JWT payload format is invalid."""

    def __init__(self, **kwargs):
        super().__init__(
            error_code="invalid_payload_format",
            error_friendly="Payload could not be deserialized",
            http_status_code=401,
            **kwargs,
        )


ErrorCode = Literal[
    "invalid_credentials",
    "expired_token",
    "invalid_token",
    "invalid_token_type",
    "invalid_user",
    "invalid_token",
    "session_not_found",
    "session_expired",
]


class APIError(Exception):
    def __init__(self, error_code: ErrorCode, http_status_code: int):
        self.error_code = error_code
        self.http_status_code = http_status_code
