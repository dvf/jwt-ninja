from typing import Literal


class JWTError(Exception):
    def __init__(self, error_code: str, error_friendly: str, http_status_code: int, **kwargs):
        self.error_code = error_code
        self.error_friendly = error_friendly
        self.http_status_code = http_status_code


class JWTExpiredError(JWTError):
    def __init__(self, **kwargs):
        super().__init__("expired_token", "Token has expired", 401, **kwargs)


class JWTInvalidTokenError(JWTError):
    def __init__(self, **kwargs):
        super().__init__("invalid_token", "Token is invalid", 401, **kwargs)


class JWTInvalidPayloadFormat(JWTError):
    def __init__(self, **kwargs):
        super().__init__("invalid_payload_format", "Payload could not be deserialized", 401, **kwargs)


ErrorCode = Literal[
    "invalid_credentials",
    "expired_token",
    "invalid_token",
    "invalid_token_type",
    "invalid_user",
    "session_not_found",
    "session_expired",
    "token_reuse_detected",
    "unsupported_media_type",
    "csrf_failed",
    "rate_limited",
]


class APIError(Exception):
    def __init__(self, error_code: ErrorCode, http_status_code: int, *, retry_after: int | None = None):
        self.error_code = error_code
        self.http_status_code = http_status_code
        self.retry_after = retry_after
