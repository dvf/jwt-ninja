---
icon: lucide/octagon-alert
---

# Error codes

Errors raised by JWT Ninja return `{"error_code": "..."}` with a matching HTTP status. Django Ninja owns request parsing, missing-authentication, and schema-validation errors; those use its standard `detail` body with status 400, 401, or 422. Clients should use `error_code` only when that field is present.

| Code                    | Status | Meaning                                                          |
| ----------------------- | ------ | ---------------------------------------------------------------- |
| `invalid_credentials`   | `401`  | Username/password did not authenticate a user.                   |
| `expired_token`         | `401`  | Token's `exp` claim is in the past.                              |
| `invalid_token`         | `401`  | Presented token signature invalid, malformed, or wrong secret.   |
| `invalid_token_type`    | `400`  | Sent an `access` token to `/refresh/`.                           |
| `invalid_token_type`    | `401`  | Sent a `refresh` token to a route protected by `JWTAuth`.        |
| `invalid_user`          | `401`  | User attached to token no longer exists or is `is_active=False`. |
| `session_not_found`     | `401`  | Session referenced by the token has been deleted.                |
| `session_not_found`     | `404`  | Id passed to `DELETE /auth/sessions/{id}/` is not one of the caller's active sessions. |
| `session_expired`       | `401`  | Session was logged out, or aged past `JWT_SESSION_EXPIRE_SECONDS`. |
| `token_reuse_detected`  | `401`  | A retired/concurrently consumed refresh token was replayed. **The session is revoked before response.** |
| `csrf_failed`           | `403`  | Django CSRF validation failed in cookie or both transport.       |
| `unsupported_media_type` | `415` | Login/refresh was not sent as a supported JSON media type.       |
| `rate_limited`          | `429`  | Default-on login/refresh throttle denied the request; see `Retry-After`. |

All auth-router responses include `Cache-Control: no-store` and `Pragma: no-cache`.
