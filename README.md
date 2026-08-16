<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/048de9e1-9141-4717-9b3e-63f828e5512f" />
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/user-attachments/assets/fe969f21-3986-4bd4-b75c-96e4e8bdf1c8" />
  <img alt="JWT Ninja Logo" src="https://github.com/user-attachments/assets/fe969f21-3986-4bd4-b75c-96e4e8bdf1c8" />
</picture>

[![PyPI](https://img.shields.io/pypi/v/jwtninja.svg)](https://pypi.python.org/pypi/jwtninja)
[![CI Status](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml/badge.svg)](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml)
[![License](https://img.shields.io/github/license/dvf/jwt-ninja)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)

*A session-backed, fully-typed authentication library for **[Django Ninja](https://django-ninja.dev/)**, powered by **[PyJWT](https://pyjwt.readthedocs.io/)**.*

**[Documentation](https://dvf.github.io/jwt-ninja/)** · **[PyPI](https://pypi.org/project/jwtninja/)** · **[Changelog](https://github.com/dvf/jwt-ninja/releases)**

---

## Why JWT Ninja

- **Stateful JWTs.** Every token maps to a `Session` row in the database. You get token-based auth plus revocation, device listing, and per-session state.
- **Fully typed.** Protected routes receive an `AuthedRequest` with typed `request.auth.user` and `request.auth.session`. OpenAPI schemas include typed error responses.
- **Three refresh-token transports.** JSON body, HttpOnly cookie, or both.
- **Complete.** Five auth endpoints, a Django admin page, a pluggable payload class for custom claims, and a pluggable authenticator for non-password login flows.

---

## Table of Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Protecting your views](#protecting-your-views)
- [Endpoints](#endpoints)
- [Error codes](#error-codes)
- [Upgrading](#upgrading)
- [Configuration](#configuration)
- [Signing key length](#signing-key-length)
- [Refresh token transport](#refresh-token-transport)
- [Refresh token rotation](#refresh-token-rotation)
- [Custom claims](#custom-claims)
- [Custom authenticator](#custom-authenticator)
- [Session management](#session-management)
- [Deployment checklist](#deployment-checklist)
- [Development](#development)

---

## Install

JWT Ninja is a standard Django app. Install it with [uv](https://astral.sh/uv) or `pip`:

```bash
uv add jwtninja
# or
pip install jwtninja
```

Requires Python **3.12+** and Django **5.x**.

Asymmetric signing algorithms (`RS*`, `ES*`, `PS*`, `EdDSA`) need PyJWT's cryptography extra:

```bash
uv add "jwtninja[crypto]"
# or
pip install "jwtninja[crypto]"
```

## Quick start

**1.** Add `jwt_ninja` to your `INSTALLED_APPS`:

```python
# settings.py
INSTALLED_APPS = [
    ...,
    "jwt_ninja",
]
```

**2.** Run migrations to create the `Session` table:

```bash
python manage.py migrate
```

**3.** Mount the router on your Ninja API and register the error handler:

```python
from ninja import NinjaAPI
from jwt_ninja import APIError
from jwt_ninja.api import router as auth_router
from jwt_ninja.handlers import error_handler

api = NinjaAPI()
api.add_router("auth/", auth_router)
api.add_exception_handler(APIError, error_handler)
```

This gives you `/auth/login/`, `/auth/refresh/`, `/auth/sessions/`, `/auth/logout/`, and `/auth/logout/all/`.

## Protecting your views

Add `auth=JWTAuth()` to any Ninja route. Annotate the request as `AuthedRequest` to get typed access to the authenticated user and session:

```python
from ninja import Router
from jwt_ninja import AuthedRequest, JWTAuth

router = Router()


@router.get("/profile/", auth=JWTAuth())
def profile(request: AuthedRequest):
    user = request.auth.user  # the Django User
    session = request.auth.session  # the jwt_ninja Session
    return {"username": user.username, "session_id": session.id}
```

### Per-session state

Each `Session` has a `JSONField` called `data`. Use it to store per-login state such as feature flags, device info, or an onboarding step:

```python
@router.post("/set-theme/", auth=JWTAuth())
def set_theme(request: AuthedRequest, theme: str):
    request.auth.session.data["theme"] = theme
    request.auth.session.save()
    return {"ok": True}
```

## Endpoints

| Method | Path                | Purpose                                         | Success | Errors              |
| ------ | ------------------- | ----------------------------------------------- | ------- | ------------------- |
| `POST` | `/auth/login/`      | Issue an access token and a refresh token       | `200`   | `401`               |
| `POST` | `/auth/refresh/`    | Refresh an access token                         | `200`   | `400`, `401`        |
| `GET`  | `/auth/sessions/`   | List the caller's active sessions               | `200`   | `401`               |
| `POST` | `/auth/logout/`     | Expire the caller's current session             | `200`   | `401`               |
| `POST` | `/auth/logout/all/` | Expire **all** of the caller's active sessions  | `200`   | `401`               |

### `POST /auth/login/`

**Request**
```json
{ "username": "alice", "password": "hunter2" }
```

**Response (`200`) in `body` mode**
```json
{ "access_token": "eyJhbGci…", "refresh_token": "eyJhbGci…" }
```

**Response (`200`) in `cookie` mode**
```json
{ "access_token": "eyJhbGci…" }
```

In `cookie` mode, the server sets the refresh token as an HttpOnly cookie and does not return it in JSON. In `both` mode, it does both.

### `POST /auth/refresh/`

**Request in `body` mode**
```json
{ "refresh_token": "eyJhbGci…" }
```

**Request in `cookie` mode**

Send the refresh token cookie that `/auth/login/` set.

**Response (`200`) in `body` mode**
```json
{ "access_token": "eyJhbGci…", "refresh_token": "eyJhbGci…" }
```

**Response (`200`) in `cookie` mode**
```json
{ "access_token": "eyJhbGci…" }
```

Refresh tokens are **rotated**. Every call to `/auth/refresh/` returns a new refresh token and retires the one you sent. Store the new token and use it for the next refresh. See [Refresh token rotation](#refresh-token-rotation).

## Error codes

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

## Upgrading

This release tightens several auth behaviors. Read these notes before you upgrade an existing deployment:

- **Refresh tokens no longer authenticate protected routes.** `JWTAuth` now requires `type == "access"`. Any other token type gets `401 invalid_token_type`. If a client sends its refresh token as a `Bearer` credential, it must switch to the access token.
- **Refresh tokens rotate on every use.** `/auth/refresh/` now returns a new `refresh_token` with the access token and retires the one you sent. Clients in `body` mode must store and use the returned token. Clients in `cookie` mode need no change. See [Refresh token rotation](#refresh-token-rotation).
- **`/auth/refresh/` now validates the session.** If the session was logged out or deleted, the server rejects the refresh token instead of minting a new access token.
- **Sessions now have a hard expiry.** Earlier versions ignored `JWT_SESSION_EXPIRE_SECONDS`, so sessions never expired. The setting now applies at session creation. Set it to `0` to keep the old behavior.
- **`expired_at` is set on live sessions.** `expired_at__isnull=True` no longer means "active". Use `Session.objects.active()` in your own queries.
- **Deleting a `User` now returns `session_not_found` on `/auth/refresh/`, not `invalid_user`.** The delete cascade removes the session first. Both codes are `401`.
- **`JWT_ALGORITHM` is validated at startup.** `none`, typos, and asymmetric algorithms without the `crypto` extra now raise `ImproperlyConfigured` instead of failing later.

Run `python manage.py migrate` to add the rotation columns.

## Configuration

All settings are Django settings prefixed with `JWT_`. Defaults shown below:

```python
# settings.py
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

### Signing key length

For HMAC algorithms (the `HS*` family, including the default `HS256`), [RFC 7518 §3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2) requires the signing key to be at least the size of the hash output:

| Algorithm | Minimum key size |
| --------- | ---------------- |
| `HS256`   | 32 bytes         |
| `HS384`   | 48 bytes         |
| `HS512`   | 64 bytes         |

Shorter keys are padded internally, which gives an attacker a smaller space to search. An attacker who recovers the key can forge tokens for any user.

**JWT Ninja emits `jwt_ninja.settings.InsecureJWTKeyWarning` at startup if your configured key is too short.** The warning appears in your app logs as soon as the settings load. PyJWT also emits its own `InsecureKeyLengthWarning` at encode/decode time.

Django's `get_random_secret_key()` already produces 50-character keys, so fresh projects are fine. Short keys typically appear in older projects or in manually set `JWT_SECRET_KEY` values. To generate a suitable key:

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

Rotating the key invalidates all existing JWT Ninja sessions, because existing tokens fail signature verification. All users must log in again after you deploy the change.

## Refresh token transport

JWT Ninja supports three refresh-token transport modes:

- **`"body"`** *(default)* — `login/` returns `refresh_token` in JSON, and `refresh/` expects it in the request body.
- **`"cookie"`** — `login/` sets the refresh token in an **HttpOnly cookie**, and `refresh/` reads it from that cookie.
- **`"both"`** — `login/` returns the refresh token in JSON **and** sets the cookie. `refresh/` accepts either the request body or the cookie.

Example browser-oriented configuration:

```python
JWT_REFRESH_TOKEN_TRANSPORT = "cookie"
JWT_REFRESH_COOKIE_SECURE = True
JWT_REFRESH_COOKIE_HTTPONLY = True
JWT_REFRESH_COOKIE_SAMESITE = "Lax"
JWT_REFRESH_COOKIE_PATH = "/auth/refresh/"
```

In `cookie` mode:

- `POST /auth/login/` returns the `access_token` in JSON and sets the refresh token cookie.
- `POST /auth/refresh/` reads the refresh token from the cookie.
- `POST /auth/logout/` and `POST /auth/logout/all/` clear the refresh token cookie.

> **Security note:** HttpOnly cookies reduce refresh-token exposure to JavaScript, but cookie-based auth flows are still subject to CSRF considerations. For browser deployments, prefer `Secure=True`, keep refresh endpoints as `POST`, and choose a `SameSite` policy that fits your application. `SameSite="None"` removes the browser's cross-site protection on the refresh endpoint. If you set it, add your own CSRF defense.

## Refresh token rotation

Every call to `/auth/refresh/` mints a **new** refresh token and retires the one you presented. Each refresh token carries a `jti` claim, and the session row records the only `jti` it currently accepts.

The server treats a retired token as evidence that the token leaked, and **revokes the whole session**. The response is `401 token_reuse_detected`. This logs out the legitimate holder along with the attacker, which is the intended outcome once a token is known to be copied.

**What clients must do:** in `body` mode, persist the `refresh_token` from every `/auth/refresh/` response and send that one next time. Replaying a stored old token will log the user out. In `cookie` mode this is automatic, because the server sets a replacement cookie each time.

### The grace window

A dropped connection can lose the refresh response. The client then retries with a token the server has already rotated past. To keep that retry from revoking a real session, the previous token stays valid for `JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS` (default `30`) after rotation.

Set it to `0` for strict single-use tokens. That choice logs out users whose refresh request gets retried.

### Upgrading existing deployments

Refresh tokens issued before rotation existed carry no `jti`, and their sessions have no recorded `jti` either. The server accepts such a token **once** and adopts the session into rotation, so upgrading does not log out your whole user base. After that first use, the old token is retired like any other.

## Custom claims

To embed extra data in the token itself (team id, feature flags, etc.), subclass `JWTPayload` and point `JWT_PAYLOAD_CLASS` at it. Encode and decode sites both use the configured class, so your custom fields round-trip end to end.

```python
# myapp/auth.py
from jwt_ninja import JWTPayload


class CustomJWTPayload(JWTPayload):
    team_id: int
    email: str
```

```python
# settings.py
JWT_PAYLOAD_CLASS = "myapp.auth.CustomJWTPayload"
```

> **Note:** If you add required fields, you also need a custom authenticator (below) or a custom login endpoint that populates them.

### Overriding `user_id`

If your User model uses a non-integer primary key (`UUIDField`, `CharField`, etc.), override `user_id` on your payload subclass. The declared type must match what `user.id` is at runtime:

```python
from uuid import UUID
from jwt_ninja import JWTPayload


class UUIDJWTPayload(JWTPayload):
    user_id: UUID  # or str, depending on your User PK


class StrPKJWTPayload(JWTPayload):
    user_id: str
```

Pydantic is strict about this. The login site passes `user.id` through without coercion, so the declared type and the runtime type must agree. The default `JWTPayload` declares `user_id: int`, which matches Django's default `AutoField` primary key.

## Custom authenticator

If you do not use Django's `username`/`password` flow (SSO, magic links, OTP, etc.), point `JWT_USER_LOGIN_AUTHENTICATOR` at a callable that returns a `User` or `None`:

```python
# myapp/auth.py
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.utils.timezone import now

User = get_user_model()


def magic_link_authenticator(request: HttpRequest, payload) -> User | None:
    try:
        return User.objects.get(magic_token=payload.token, magic_token_expired_at__gt=now())
    except User.DoesNotExist:
        return None
```

```python
# settings.py
JWT_USER_LOGIN_AUTHENTICATOR = "myapp.auth.magic_link_authenticator"
```

The callable receives the raw `HttpRequest` and the parsed `LoginSchema` payload. If it returns `None`, the response is `401 invalid_credentials`.

## Session management

The `Session` model has helpers for common auth tasks.

### Invalidate all sessions (e.g., on password change)

```python
from jwt_ninja.models import Session

# On password change, log the user out of every device
Session.invalidate_all_user_sessions(user)
```

This runs one bulk `UPDATE` that sets `expired_at` on every active session for the user.

### Purge expired sessions (e.g., nightly cron)

Over time, rows accumulate for sessions long past their `expired_at`. Delete them with a scheduled task:

```python
from jwt_ninja.models import Session

# Run from django-crontab, Celery beat, or a management command
Session.purge_expired_sessions()
```

### Inspect sessions in the admin

`jwt_ninja` registers a read-only `SessionAdmin` at `/admin/jwt_ninja/session/`. Use it to see which users are logged in, and from where.

> **On the recorded IP address:** `Session.ip_address` prefers the first entry in `X-Forwarded-For` and falls back to `REMOTE_ADDR`. Non-IP values are discarded rather than stored. Any client can send `X-Forwarded-For`, so the value is only trustworthy if a proxy you control overwrites the header on the way in. Treat it as a hint for support and debugging, not as evidence in an investigation.

## Deployment checklist

JWT Ninja deliberately leaves these tasks to your application:

- **Rate-limit `/auth/login/`.** Nothing in JWT Ninja throttles password guessing. Put a throttle in front of the endpoint: Django Ninja's built-in throttling, `django-ratelimit`, or your reverse proxy or WAF. Consider a rate limit on `/auth/refresh/` too.
- **Schedule `Session.purge_expired_sessions()`.** Sessions carry a hard expiry, but nothing deletes the rows until you run the purge. See [Purge expired sessions](#purge-expired-sessions-eg-nightly-cron).
- **Serve over HTTPS.** Access tokens are bearer credentials. Anyone who observes one can use it until it expires.
- **Keep `JWT_ACCESS_TOKEN_EXPIRE_SECONDS` short.** Every request checks the access token against the DB session, so revocation is quick. A short lifetime is still your backstop.
- **Set a strong signing key.** See [Signing key length](#signing-key-length).

## Development

```bash
# Clone and install
git clone https://github.com/dvf/jwt-ninja
cd jwt-ninja
uv sync

# Run tests
uv run pytest

# Lint + format
uv run ruff check .
uv run ruff format .

# Static type check
uv run pyrefly check
```

PRs are gated on all four checks. See [`.github/workflows/check-and-test.yml`](.github/workflows/check-and-test.yml).

---

## License

MIT — see [LICENSE](LICENSE).
