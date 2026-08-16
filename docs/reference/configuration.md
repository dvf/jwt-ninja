---
icon: lucide/settings
---

# Configuration

All settings are Django settings prefixed with `JWT_`. Defaults shown below:

```python title="settings.py"
JWT_SECRET_KEY = SECRET_KEY  # Defaults to Django's SECRET_KEY
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_SECONDS = 300  # 5 minutes
JWT_REFRESH_TOKEN_EXPIRE_SECONDS = 365 * 3600  # ~15 days
JWT_SESSION_EXPIRE_SECONDS = 365 * 3600  # ~15 days (0 disables session expiry)
JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS = 30  # 0 disables the grace window
JWT_USER_LOGIN_AUTHENTICATOR = "jwt_ninja.authenticators.django_user_authenticator"
JWT_PAYLOAD_CLASS = "jwt_ninja.types.JWTPayload"
JWT_REFRESH_TOKEN_TRANSPORT = "body"  # "body", "cookie", or "both"
JWT_REFRESH_COOKIE_NAME = "refresh_token"
JWT_REFRESH_COOKIE_SECURE = True
JWT_REFRESH_COOKIE_HTTPONLY = True
JWT_REFRESH_COOKIE_SAMESITE = "Lax"  # "Lax", "Strict", or "None"
JWT_REFRESH_COOKIE_PATH = "/auth/refresh/"
JWT_REFRESH_COOKIE_DOMAIN = None
```

| Setting                              | Type                               | Description                                                                                     |
| ------------------------------------ | ---------------------------------- | ----------------------------------------------------------------------------------------------- |
| `JWT_SECRET_KEY`                     | `str`                              | Signing key. Defaults to Django's `SECRET_KEY`. See [Signing key length](#signing-key-length). |
| `JWT_ALGORITHM`                      | `str`                              | PyJWT algorithm. Symmetric (`HS*`) or asymmetric (`RS*`, `ES*`, …). Validated at startup. `none` is rejected. Asymmetric algorithms require `pip install 'jwtninja[crypto]'`. |
| `JWT_ACCESS_TOKEN_EXPIRE_SECONDS`    | `int`                              | Lifetime of the short-lived access token.                                                      |
| `JWT_REFRESH_TOKEN_EXPIRE_SECONDS`   | `int`                              | Lifetime of the refresh token.                                                                 |
| `JWT_SESSION_EXPIRE_SECONDS`         | `int`                              | Hard max age applied to a `Session` at creation. `0` means sessions live until logged out.     |
| `JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS` | `int`                           | Seconds a just-rotated refresh token stays valid, so a retried request is not read as a replay. `0` enforces strict single use. |
| `JWT_USER_LOGIN_AUTHENTICATOR`       | `str`                              | Dotted path to a callable `(request, payload) -> User \| None` used by `/auth/login/`.         |
| `JWT_PAYLOAD_CLASS`                  | `str`                              | Dotted path to a `JWTPayload` subclass if you need custom claims.                              |
| `JWT_REFRESH_TOKEN_TRANSPORT`        | `"body" \| "cookie" \| "both"` | Where refresh tokens are returned and read.                                                    |
| `JWT_REFRESH_COOKIE_NAME`            | `str`                              | Cookie name used when cookie transport is enabled.                                             |
| `JWT_REFRESH_COOKIE_SECURE`          | `bool`                             | Sets the cookie's `Secure` flag.                                                               |
| `JWT_REFRESH_COOKIE_HTTPONLY`        | `bool`                             | Sets the cookie's `HttpOnly` flag.                                                             |
| `JWT_REFRESH_COOKIE_SAMESITE`        | `"Lax" \| "Strict" \| "None"` | Sets the cookie's `SameSite` policy.                                                           |
| `JWT_REFRESH_COOKIE_PATH`            | `str`                              | Restricts the cookie to the refresh endpoint path.                                             |
| `JWT_REFRESH_COOKIE_DOMAIN`          | `str \| None`                     | Optional cookie domain override.                                                               |

## Signing key length

For HMAC algorithms (the `HS*` family, including the default `HS256`), [RFC 7518 §3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2) requires the signing key to be at least the size of the hash output:

| Algorithm | Minimum key size |
| --------- | ---------------- |
| `HS256`   | 32 bytes         |
| `HS384`   | 48 bytes         |
| `HS512`   | 64 bytes         |

Shorter keys are padded internally, which gives an attacker a smaller space to search. An attacker who recovers the key can forge tokens for any user.

!!! warning

    JWT Ninja emits `jwt_ninja.settings.InsecureJWTKeyWarning` at startup if your configured key is too short. The warning appears in your app logs as soon as the settings load. PyJWT also emits its own `InsecureKeyLengthWarning` at encode/decode time.

Django's `get_random_secret_key()` already produces 50-character keys, so fresh projects are fine. Short keys typically appear in older projects or in manually set `JWT_SECRET_KEY` values. To generate a suitable key:

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

Rotating the key invalidates all existing JWT Ninja sessions, because existing tokens fail signature verification. All users must log in again after you deploy the change.
