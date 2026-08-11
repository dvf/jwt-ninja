<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/048de9e1-9141-4717-9b3e-63f828e5512f" />
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/user-attachments/assets/fe969f21-3986-4bd4-b75c-96e4e8bdf1c8" />
  <img alt="JWT Ninja Logo" src="https://github.com/user-attachments/assets/fe969f21-3986-4bd4-b75c-96e4e8bdf1c8" />
</picture>

<br/>

# JWT Ninja

*A session‑backed, fully‑typed authentication library for **[Django Ninja](https://django-ninja.dev/)**, powered by **[PyJWT](https://pyjwt.readthedocs.io/)**.*

[![PyPI](https://img.shields.io/pypi/v/jwtninja.svg)](https://pypi.python.org/pypi/jwtninja)
[![CI Status](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml/badge.svg)](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml)
[![License](https://img.shields.io/github/license/dvf/jwt-ninja)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)

> **❤️ Contributions Welcome!** Feel free to submit a PR.

---

## Why JWT Ninja

- **Stateful JWTs.** Every token is tied to a DB-backed `Session` row — so you get token-based auth *and* revocation, device listing, and per-session state.
- **Fully typed.** Protected routes receive an `AuthedRequest` with `request.auth.user` and `request.auth.session` typed; OpenAPI schemas are generated with typed error responses.
- **Flexible refresh-token transport.** Use JSON body transport, HttpOnly cookies, or both.
- **Batteries included.** Five auth endpoints, a Django admin page, pluggable payload class for custom claims, pluggable authenticator for non-password login flows.

---

## Upgrading

This release tightens several auth behaviours. Existing deployments should read these before upgrading:

- **Refresh tokens no longer authenticate protected routes.** `JWTAuth` now requires `type == "access"` and returns `401 invalid_token_type` otherwise. If any client was sending its refresh token as a `Bearer` credential, it must switch to the access token.
- **Refresh tokens are rotated on every use.** `/auth/refresh/` now returns a new `refresh_token` alongside the access token, and retires the one you sent. `body`-mode clients must persist and use the returned token; `cookie`-mode clients need no change. See [Refresh token rotation](#refresh-token-rotation).
- **`/auth/refresh/` now validates the session.** A refresh token whose session was logged out or deleted is rejected instead of minting a new access token.
- **Sessions now carry a hard expiry.** `JWT_SESSION_EXPIRE_SECONDS` was previously ignored and sessions never aged out. It is now applied at session creation; set it to `0` to keep the old behaviour.
- **`expired_at` is set on live sessions**, so `expired_at__isnull=True` no longer means "active". Use `Session.objects.active()` in your own queries.
- **Deleting a `User` now surfaces as `session_not_found`** rather than `invalid_user` on `/auth/refresh/`, because the cascade removes the session first. Both are `401`.
- **`JWT_ALGORITHM` is validated at startup.** `none`, typos, and asymmetric algorithms without the `crypto` extra now raise `ImproperlyConfigured` instead of failing later.

Run `python manage.py migrate` to add the rotation columns.

## Table of Contents

- [Install](#install)
- [Quick Start](#quick-start)
- [Protecting Your Views](#protecting-your-views)
- [Endpoints](#endpoints)
- [Error Codes](#error-codes)
- [Upgrading](#upgrading)
- [Configuration](#configuration)
- [Signing key length](#signing-key-length)
- [Refresh token transport](#refresh-token-transport)
- [Refresh token rotation](#refresh-token-rotation)
- [Custom Claims](#custom-claims)
- [Custom Authenticator](#custom-authenticator)
- [Session Management](#session-management)
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

## Quick Start

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

**3.** Mount the router on your Ninja API and wire up the error handler:

```python
from ninja import NinjaAPI
from jwt_ninja import APIError
from jwt_ninja.api import router as auth_router
from jwt_ninja.handlers import error_handler

api = NinjaAPI()
api.add_router("auth/", auth_router)
api.add_exception_handler(APIError, error_handler)
```

That's it — you now have `/auth/login/`, `/auth/refresh/`, `/auth/sessions/`, `/auth/logout/`, and `/auth/logout/all/`.

## Protecting Your Views

Decorate any Ninja route with `auth=JWTAuth()` and annotate the request as `AuthedRequest` for typed access to the authenticated user and session:

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

Each `Session` has a `JSONField` called `data` that you can use as scratch space for per-login state (feature flags, device info, onboarding step, etc.):

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
| `POST` | `/auth/login/`      | Issue a new **access** token and refresh token transport | `200`   | `401`               |
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

In `cookie` mode, the refresh token is set as an HttpOnly cookie instead of being returned in JSON. In `both` mode, JWT Ninja does both.

### `POST /auth/refresh/`

**Request in `body` mode**
```json
{ "refresh_token": "eyJhbGci…" }
```

**Request in `cookie` mode**

Send the refresh token cookie previously set by `/auth/login/`.

**Response (`200`) in `body` mode**
```json
{ "access_token": "eyJhbGci…", "refresh_token": "eyJhbGci…" }
```

**Response (`200`) in `cookie` mode**
```json
{ "access_token": "eyJhbGci…" }
```

Refresh tokens are **rotated**: every call to `/auth/refresh/` returns a new refresh token and retires the one you sent. Store the new token and use it for the next refresh — see [Refresh token rotation](#refresh-token-rotation).

## Error Codes

All errors are returned as a JSON body `{"error_code": "..."}` with an appropriate HTTP status. Use these for i18n-friendly UX on the client.

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
| `JWT_ALGORITHM`                      | `str`                              | PyJWT algorithm. Symmetric (`HS*`) or asymmetric (`RS*`, `ES*`, …). Validated at startup; `none` is rejected. Asymmetric algorithms require `pip install 'jwtninja[crypto]'`. |
| `JWT_ACCESS_TOKEN_EXPIRE_SECONDS`    | `int`                              | Lifetime of the short-lived access token.                                                      |
| `JWT_REFRESH_TOKEN_EXPIRE_SECONDS`   | `int`                              | Lifetime of the refresh token.                                                                 |
| `JWT_SESSION_EXPIRE_SECONDS`         | `int`                              | Hard max age applied to a `Session` at creation. `0` means sessions live until logged out.     |
| `JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS` | `int`                           | How long a just-rotated refresh token is still accepted, so a retried request isn't read as a replay. `0` enforces strict single-use. |
| `JWT_USER_LOGIN_AUTHENTICATOR`       | `str`                              | Dotted path to a callable `(request, payload) -> User \| None` used by `/auth/login/`.         |
| `JWT_PAYLOAD_CLASS`                  | `str`                              | Dotted path to a `JWTPayload` subclass if you need custom claims.                              |
| `JWT_REFRESH_TOKEN_TRANSPORT`        | `"body" \| "cookie" \| "both"` | Where refresh tokens are returned/read.                                                        |
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

Shorter keys are padded internally and give attackers a smaller space to search — an attacker who recovers the key can forge arbitrary tokens for any user.

**JWT Ninja emits `jwt_ninja.settings.InsecureJWTKeyWarning` at startup if your configured key is too short**, so you'll see it in your app logs as soon as the settings load. PyJWT also emits its own `InsecureKeyLengthWarning` at encode/decode time.

Django's `get_random_secret_key()` already produces 50-character keys, so fresh projects are fine. Short keys typically show up in older projects or in manually-set `JWT_SECRET_KEY` values. To generate a suitable key:

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

Rotating the key invalidates all existing JWT Ninja sessions (existing tokens fail signature verification), so users will need to re-authenticate after deploying the change.

## Refresh token transport

JWT Ninja supports three refresh-token transport modes:

- **`"body"`** *(default)* — `login/` returns `refresh_token` in JSON and `refresh/` expects it in the request body.
- **`"cookie"`** — `login/` sets the refresh token in an **HttpOnly cookie** and `refresh/` reads it from that cookie.
- **`"both"`** — `login/` returns the refresh token in JSON **and** sets the cookie; `refresh/` accepts either the request body or the cookie.

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

> **Security note:** HttpOnly cookies reduce refresh-token exposure to JavaScript, but cookie-based auth flows are still subject to CSRF considerations. For browser deployments, prefer `Secure=True`, keep refresh endpoints as `POST`, and choose an appropriate `SameSite` policy for your application. `SameSite="None"` removes the browser's cross-site protection on the refresh endpoint — if you set it, add your own CSRF defence.

## Refresh token rotation

Every call to `/auth/refresh/` mints a **new** refresh token and retires the one you presented. Each refresh token carries a `jti` claim, and the session row records the only `jti` it currently accepts.

Presenting a retired token is treated as evidence that the token leaked, and **the whole session is revoked** — the legitimate holder is logged out along with the attacker, which is the intended outcome once a token is known to be copied. The response is `401 token_reuse_detected`.

**What clients must do:** in `body` mode, persist the `refresh_token` from every `/auth/refresh/` response and send that one next time. Replaying a stored token will log the user out. In `cookie` mode this is automatic — the server sets a replacement cookie each time.

### The grace window

A client whose refresh response is lost to a dropped connection will retry with a token the server has already rotated past. To keep that from revoking real sessions, the immediately-previous token stays valid for `JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS` (default `30`) after rotation.

Set it to `0` for strict single-use tokens, at the cost of logging out users whose refresh request gets retried.

### Upgrading existing deployments

Refresh tokens issued before rotation existed carry no `jti`, and their sessions have no recorded `jti` either. Such a token is honoured **once**, adopting the session into rotation, so upgrading doesn't log your whole userbase out. After that first use the old token is retired like any other.

## Custom Claims

Need to embed extra data in the token itself (team id, feature flags, etc.)? Subclass `JWTPayload` and point `JWT_PAYLOAD_CLASS` at it — encode *and* decode sites both use the configured class, so your custom fields round-trip end-to-end.

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

> **Note:** If you add required fields, you'll also need a custom authenticator (below) or a custom login endpoint that knows how to populate them.

### Overriding `user_id`

If your User model uses a non-integer primary key (`UUIDField`, `CharField`, etc.), override `user_id` on your payload subclass so the declared type matches what `user.id` actually is at runtime:

```python
from uuid import UUID
from jwt_ninja import JWTPayload


class UUIDJWTPayload(JWTPayload):
    user_id: UUID  # or str, depending on your User PK


class StrPKJWTPayload(JWTPayload):
    user_id: str
```

Pydantic is strict about this: `user_id=user.id` at the login site passes the PK through without coercion, so the declared type and the runtime type must agree. The default `JWTPayload` declares `user_id: int`, which matches Django's default `AutoField` primary key.

## Custom Authenticator

If you don't use Django's `username`/`password` flow (SSO, magic links, OTP, etc.), point `JWT_USER_LOGIN_AUTHENTICATOR` at a callable that returns a `User` or `None`:

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

The callable receives the raw `HttpRequest` and the parsed `LoginSchema` payload. Returning `None` produces a `401 invalid_credentials` response.

## Session Management

The `Session` model exposes a small set of helpers for common auth chores.

### Invalidate all sessions (e.g., on password change)

```python
from jwt_ninja.models import Session

# On password change, log the user out of every device
Session.invalidate_all_user_sessions(user)
```

This is a single bulk `UPDATE` that flips `expired_at` on every active session for the user.

### Purge expired sessions (e.g., nightly cron)

Over time you'll accumulate rows for sessions that are long past their `expired_at`. Purge them with a scheduled task:

```python
from jwt_ninja.models import Session

# django-crontab, Celery beat, management command, whatever you prefer
Session.purge_expired_sessions()
```

### Inspect sessions in the admin

`jwt_ninja` registers a read-only `SessionAdmin` so ops can see who's logged in from where — just visit `/admin/jwt_ninja/session/`.

> **On the recorded IP address:** `Session.ip_address` prefers the first entry in `X-Forwarded-For` and falls back to `REMOTE_ADDR`, and non-IP values are discarded rather than stored. Any client can send `X-Forwarded-For`, so the value is only trustworthy if a proxy you control overwrites the header on the way in. Treat it as a hint for support and debugging, not as evidence in an investigation.

## Deployment checklist

Things JWT Ninja deliberately leaves to your application:

- **Rate-limit `/auth/login/`.** Nothing here throttles password guessing. Put a throttle in front of it — Django Ninja's built-in throttling, `django-ratelimit`, or your reverse proxy / WAF. Consider rate-limiting `/auth/refresh/` too.
- **Schedule `Session.purge_expired_sessions()`.** Sessions now carry a hard expiry, but nothing deletes the rows until you run the purge. See [Purge expired sessions](#purge-expired-sessions-eg-nightly-cron).
- **Serve over HTTPS.** Access tokens are bearer credentials; anyone who observes one can use it until it expires.
- **Keep `JWT_ACCESS_TOKEN_EXPIRE_SECONDS` short.** Access tokens are checked against the DB session on every request, so revocation is quick — but a short lifetime is still your backstop.
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
