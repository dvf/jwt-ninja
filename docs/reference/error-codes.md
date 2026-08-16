---
icon: lucide/octagon-alert
---

# Error codes

Every error returns a JSON body `{"error_code": "..."}` with a matching HTTP status. Use the codes to build client-side messages and translations.

| Code                    | Status | Meaning                                                          |
| ----------------------- | ------ | ---------------------------------------------------------------- |
| `invalid_credentials`   | `401`  | Username/password did not authenticate a user.                   |
| `expired_token`         | `401`  | Token's `exp` claim is in the past.                              |
| `invalid_token`         | `401`  | Token signature invalid, malformed, wrong secret, or missing.    |
| `invalid_token_type`    | `400`  | Sent an `access` token to `/refresh/`.                           |
| `invalid_token_type`    | `401`  | Sent a `refresh` token to a route protected by `JWTAuth`.        |
| `invalid_user`          | `401`  | User attached to token no longer exists or is `is_active=False`. |
| `session_not_found`     | `401`  | Session referenced by the token has been deleted.                |
| `session_expired`       | `401`  | Session was logged out, or aged past `JWT_SESSION_EXPIRE_SECONDS`. |
| `token_reuse_detected`  | `401`  | A retired refresh token was replayed. **The session is revoked.** |
