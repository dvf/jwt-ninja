<img width="400" height="177" alt="JWT Ninja Logo" src="https://github.com/user-attachments/assets/b502f660-027c-4516-b265-4136b2b1b7e7" />

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
- **Batteries included.** Five auth endpoints, a Django admin page, pluggable payload class for custom claims, pluggable authenticator for non-password login flows.

---

## Table of Contents

- [Install](#install)
- [Quick Start](#quick-start)
- [Protecting Your Views](#protecting-your-views)
- [Endpoints](#endpoints)
- [Error Codes](#error-codes)
- [Configuration](#configuration)
- [Custom Claims](#custom-claims)
- [Custom Authenticator](#custom-authenticator)
- [Session Management](#session-management)
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
    user = request.auth.user        # the Django User
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
| `POST` | `/auth/login/`      | Issue a new **access** & **refresh** token pair | `200`   | `401`               |
| `POST` | `/auth/refresh/`    | Refresh an access token                         | `200`   | `400`, `401`        |
| `GET`  | `/auth/sessions/`   | List the caller's active sessions               | `200`   | `401`               |
| `POST` | `/auth/logout/`     | Expire the caller's current session             | `200`   | `401`               |
| `POST` | `/auth/logout/all/` | Expire **all** of the caller's active sessions  | `200`   | `401`               |

### `POST /auth/login/`

**Request**
```json
{ "username": "alice", "password": "hunter2" }
```

**Response (`200`)**
```json
{ "access_token": "eyJhbGci…", "refresh_token": "eyJhbGci…" }
```

### `POST /auth/refresh/`

**Request**
```json
{ "refresh_token": "eyJhbGci…" }
```

**Response (`200`)**
```json
{ "access_token": "eyJhbGci…" }
```

## Error Codes

All errors are returned as a JSON body `{"error_code": "..."}` with an appropriate HTTP status. Use these for i18n-friendly UX on the client.

| Code                    | Status | Meaning                                                        |
| ----------------------- | ------ | -------------------------------------------------------------- |
| `invalid_credentials`   | `401`  | Username/password did not authenticate a user.                 |
| `expired_token`         | `401`  | Token's `exp` claim is in the past.                            |
| `invalid_token`         | `401`  | Token signature invalid, malformed, or wrong secret.           |
| `invalid_token_type`    | `400`  | Sent an `access` token to `/refresh/` or similar.              |
| `invalid_user`          | `401`  | User attached to token no longer exists or is `is_active=False`. |
| `session_not_found`     | `401`  | Session referenced by the token has been deleted.              |
| `session_expired`       | `401`  | Session was explicitly logged out or has an `expired_at`.      |

## Configuration

All settings are Django settings prefixed with `JWT_`. Defaults shown below:

```python
# settings.py
JWT_SECRET_KEY = SECRET_KEY                    # Defaults to Django's SECRET_KEY
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_SECONDS = 300          # 5 minutes
JWT_REFRESH_TOKEN_EXPIRE_SECONDS = 365 * 3600  # 1 year
JWT_SESSION_EXPIRE_SECONDS = 365 * 3600        # 1 year
JWT_USER_LOGIN_AUTHENTICATOR = "jwt_ninja.authenticators.django_user_authenticator"
JWT_PAYLOAD_CLASS = "jwt_ninja.types.JWTPayload"
```

| Setting                              | Type  | Description                                                                                   |
| ------------------------------------ | ----- | --------------------------------------------------------------------------------------------- |
| `JWT_SECRET_KEY`                     | `str` | Signing key. Defaults to Django's `SECRET_KEY`.                                               |
| `JWT_ALGORITHM`                      | `str` | PyJWT algorithm. Symmetric (`HS*`) or asymmetric (`RS*`, `ES*`, …).                          |
| `JWT_ACCESS_TOKEN_EXPIRE_SECONDS`    | `int` | Lifetime of the short-lived access token.                                                    |
| `JWT_REFRESH_TOKEN_EXPIRE_SECONDS`   | `int` | Lifetime of the refresh token.                                                               |
| `JWT_SESSION_EXPIRE_SECONDS`         | `int` | Max age of the DB `Session` row before it's considered expired by housekeeping.              |
| `JWT_USER_LOGIN_AUTHENTICATOR`       | `str` | Dotted path to a callable `(request, payload) -> User \| None` used by `/auth/login/`.       |
| `JWT_PAYLOAD_CLASS`                  | `str` | Dotted path to a `JWTPayload` subclass if you need custom claims.                            |

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
from django.http import HttpRequest
from django.contrib.auth import get_user_model

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
