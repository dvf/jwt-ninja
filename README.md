<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/048de9e1-9141-4717-9b3e-63f828e5512f" />
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/user-attachments/assets/fe969f21-3986-4bd4-b75c-96e4e8bdf1c8" />
  <img alt="JWT Ninja Logo" src="https://github.com/user-attachments/assets/fe969f21-3986-4bd4-b75c-96e4e8bdf1c8" />
</picture>

*A session-backed, fully-typed authentication library for **[Django Ninja](https://django-ninja.dev/)**, powered by **[PyJWT](https://pyjwt.readthedocs.io/)**.*

[![PyPI](https://img.shields.io/pypi/v/jwtninja.svg)](https://pypi.python.org/pypi/jwtninja)
[![CI Status](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml/badge.svg)](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml)
[![License](https://img.shields.io/github/license/dvf/jwt-ninja)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)
![PyPI - Downloads](https://img.shields.io/pypi/dw/jwtninja)

---

**[Documentation](https://dvf.github.io/jwt-ninja/)** · **[PyPI](https://pypi.org/project/jwtninja/)** · **[Changelog](https://github.com/dvf/jwt-ninja/releases)**

---

## Why JWT Ninja

- **Stateful JWTs.** Every token maps to a `Session` row in the database. You get token-based auth plus instant revocation and per-session state.
- **Built-in device management.** Each user gets a session list with IP address, browser, and location. Users can sign out one device or all devices. See [Device management](#device-management).
- **Fully typed.** Protected routes receive an `AuthedRequest` with typed `request.auth.user` and `request.auth.session`. OpenAPI schemas include typed error responses.
- **Three refresh-token transports.** JSON body, HttpOnly cookie, or both.
- **Complete.** Seven auth endpoints, a Django admin page, a pluggable payload class for custom claims, a pluggable authenticator for non-password login flows, and a pluggable geolocation provider for the session list.

---

## Table of Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Protecting your views](#protecting-your-views)
- [Device management](#device-management)
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

Requires Python **3.12+** and Django **5.2.16 through 6.1** (`>=5.2.16,<6.2`).

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

**2.** Configure a dedicated signing profile. These settings are required; Django's `SECRET_KEY` is never used as a fallback:

```python
JWT_SECRET_KEY = "a-separate-random-key-of-at-least-32-bytes"
JWT_ISSUER = "https://auth.example.com"
JWT_AUDIENCE = "example-api"
# Asymmetric algorithms additionally require JWT_VERIFYING_KEY (the public key).
```

**3.** Run migrations to create the `Session` table:

```bash
python manage.py migrate
```

**4.** Mount the router on your Ninja API and register the error handler:

```python
from ninja import NinjaAPI
from jwt_ninja import APIError
from jwt_ninja.api import router as auth_router
from jwt_ninja.handlers import error_handler

api = NinjaAPI()
api.add_router("auth/", auth_router)
api.add_exception_handler(APIError, error_handler)
```

This gives you `/auth/csrf/`, `/auth/login/`, `/auth/refresh/`, `/auth/sessions/`, `/auth/sessions/{id}/`, `/auth/logout/`, and `/auth/logout/all/`. All auth responses carry `Cache-Control: no-store` and `Pragma: no-cache`.

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

## Device management

Most JWT libraries stop after they issue a token. Because every JWT Ninja token maps to a database session, your users get the "where am I signed in?" screen they know from Google or GitHub. No extra services, no extra dependencies.

`GET /auth/sessions/` returns one row for each logged-in device:

```json
[
  {
    "id": "8dKt2…",
    "created_at": "2026-08-16T09:12:03Z",
    "last_activity_at": "2026-08-16T11:47:20Z",
    "ip_address": "203.0.113.42",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) … Chrome/126.0.0.0 Safari/537.36",
    "browser": "Chrome on macOS",
    "location": {
      "city": "Amsterdam",
      "region": "North Holland",
      "country": "Netherlands",
      "country_code": "NL",
      "latitude": 52.37,
      "longitude": 4.89
    },
    "is_current": true
  }
]
```

- At login, JWT Ninja records the client IP address and the `User-Agent` header.
- `browser` is a summary of the recorded `User-Agent`, for example "Chrome on macOS". JWT Ninja parses it in-process, with no added dependency.
- `location` shows where the login came from. It is `null` until you configure a [geolocation provider](#session-geolocation).
- `is_current` is `true` on the session that makes the request. Use it to label "this device" and to warn before sign-out.

Users can sign out of any session:

| Action                    | Endpoint                       |
| ------------------------- | ------------------------------ |
| Sign out this device      | `POST /auth/logout/`           |
| Sign out one other device | `DELETE /auth/sessions/{id}/`  |
| Sign out all devices      | `POST /auth/logout/all/`       |

A revoked session immediately stops both its access tokens and its refresh tokens.

### Session geolocation

Geolocation is off by default. To fill the `location` field, point `JWT_GEOLOCATION_PROVIDER` at a callable. JWT Ninja includes a free provider backed by [ipapi.co](https://ipapi.co) — HTTPS, no API key, approximately 1,000 lookups per day:

```python
# settings.py
JWT_GEOLOCATION_PROVIDER = "jwt_ninja.geolocation.ipapi_co_geolocator"
JWT_GEOLOCATION_THIRD_PARTY_CONSENT = True  # explicit consent to send client IPs
```

The provider runs one time per login, and JWT Ninja stores the result on the session. The list endpoint reads the stored value and does no lookups. If the provider fails, JWT Ninja logs the error and completes the login without a location. JWT Ninja does not send private, loopback, or other non-routable addresses to the provider.

To use an offline database or a paid API, write your own provider. Any callable `(ip: str) -> GeoLocation | None` works. An offline database avoids the per-login HTTP round-trip and third-party rate limits:

```python
# myapp/geo.py — offline lookups via MaxMind GeoLite2 and Django's GeoIP2
from django.contrib.gis.geoip2 import GeoIP2
from jwt_ninja import GeoLocation


def geoip2_geolocator(ip_address: str) -> GeoLocation | None:
    match = GeoIP2().city(ip_address)
    return GeoLocation(
        city=match["city"],
        country=match["country_name"],
        country_code=match["country_code"],
        latitude=match["latitude"],
        longitude=match["longitude"],
    )
```

```python
# settings.py
JWT_GEOLOCATION_PROVIDER = "myapp.geo.geoip2_geolocator"
```

> **Privacy note:** an HTTP provider sends your users' IP addresses to a third party at each login. If this conflicts with your privacy or compliance requirements, use an offline database or keep geolocation off.

## Endpoints

| Method   | Path                    | Purpose                                         | Success | Errors              |
| -------- | ----------------------- | ----------------------------------------------- | ------- | ------------------- |
| `GET`    | `/auth/csrf/`           | Bootstrap Django CSRF for browser cookie flows  | `200`   | —                   |
| `POST`   | `/auth/login/`          | Issue an access token and a refresh token       | `200`   | `401`               |
| `POST`   | `/auth/refresh/`        | Refresh an access token                         | `200`   | `400`, `401`        |
| `GET`    | `/auth/sessions/`       | List the caller's active sessions               | `200`   | `401`               |
| `DELETE` | `/auth/sessions/{id}/`  | Revoke a single session                         | `200`   | `401`, `404`        |
| `POST`   | `/auth/logout/`         | Expire the caller's current session             | `200`   | `401`               |
| `POST`   | `/auth/logout/all/`     | Expire **all** of the caller's active sessions  | `200`   | `401`               |

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

Send `{}` as an `application/json` body with the refresh token cookie. Browser clients first call `GET /auth/csrf/`, then send the returned masked token in `X-CSRFToken` on both login and refresh. Cookie and `both` modes always enforce Django CSRF, even when a body token is present.

**Response (`200`) in `body` mode**
```json
{ "access_token": "eyJhbGci…", "refresh_token": "eyJhbGci…" }
```

**Response (`200`) in `cookie` mode**
```json
{ "access_token": "eyJhbGci…" }
```

Refresh tokens are **rotated**. Every call to `/auth/refresh/` returns a new refresh token and retires the one you sent. Store the new token and use it for the next refresh. See [Refresh token rotation](#refresh-token-rotation).

### `GET /auth/sessions/`

Returns every active session for the authenticated user — one row per logged-in device. See [Device management](#device-management) for an example payload and the field semantics.

### `DELETE /auth/sessions/{id}/`

Revokes one session — the "sign out that device" action in a session list. If the id is not one of the caller's own active sessions, the response is `404 session_not_found`. Ids that belong to another user, expired ids, and unknown ids are deliberately indistinguishable. If the caller revokes its current session, the effect is the same as `logout/`. Under cookie transport, that includes clearing the refresh cookie.

## Error codes

Errors raised by JWT Ninja return `{"error_code": "..."}` with a matching HTTP status. Django Ninja owns request parsing, missing-authentication, and schema validation failures, which use its standard `detail` body with status 400, 401, or 422. Use `error_code` only when that field is present.

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
| `token_reuse_detected`  | `401`  | A retired refresh token was replayed. **The session is revoked.** |

## Upgrading

This release tightens several auth behaviors. Read these notes before you upgrade an existing deployment:

- **Runtime floor:** Python 3.12+ and Django >=5.2.16,<6.2 are required; Django 5.0 and 5.1 are no longer supported.
- **Deploy atomically:** do not run mixed old/new authentication workers. Old workers issue legacy-profile tokens that new workers reject. Migrate and replace the worker fleet as one coordinated forced-reauthentication rollout.

- **Refresh tokens no longer authenticate protected routes.** `JWTAuth` now requires `type == "access"`. Any other token type gets `401 invalid_token_type`. If a client sends its refresh token as a `Bearer` credential, it must switch to the access token.
- **Refresh tokens rotate on every use.** `/auth/refresh/` now returns a new `refresh_token` with the access token and retires the one you sent. Clients in `body` mode must store and use the returned token. Clients in `cookie` mode need no change. See [Refresh token rotation](#refresh-token-rotation).
- **`/auth/refresh/` now validates the session.** If the session was logged out or deleted, the server rejects the refresh token instead of minting a new access token.
- **Sessions now have a hard expiry.** Earlier versions ignored `JWT_SESSION_EXPIRE_SECONDS`, so sessions never expired. The setting now applies at session creation. Set it to `0` to keep the old behavior.
- **`expired_at` is set on live sessions.** `expired_at__isnull=True` no longer means "active". Use `Session.objects.active()` in your own queries.
- **Deleting a `User` now returns `session_not_found` on `/auth/refresh/`, not `invalid_user`.** The delete cascade removes the session first. Both codes are `401`.
- **`JWT_ALGORITHM` is validated at startup.** `none`, typos, and asymmetric algorithms without the `crypto` extra now raise `ImproperlyConfigured` instead of failing later.
- **Sessions now record the login `User-Agent`, and optionally a geolocation.** `GET /auth/sessions/` returns `user_agent`, `browser`, `location`, and `is_current` alongside the existing fields. Geolocation stays off until you set [`JWT_GEOLOCATION_PROVIDER`](#session-geolocation).
- **New endpoint: `DELETE /auth/sessions/{id}/`** revokes a single session, so clients can offer per-device sign-out.

Run `python manage.py migrate` to add the rotation and device columns.

## Configuration

All settings are Django settings prefixed with `JWT_`. Defaults shown below:

```python
# settings.py
JWT_SECRET_KEY = "required-dedicated-key-at-least-32-bytes"
JWT_VERIFYING_KEY = None  # required and separate for asymmetric algorithms
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "https://auth.example.com"  # required
JWT_AUDIENCE = "example-api"  # required
JWT_LEEWAY_SECONDS = 0
JWT_ACCESS_TOKEN_EXPIRE_SECONDS = 300  # 5 minutes
JWT_REFRESH_TOKEN_EXPIRE_SECONDS = 14 * 86400  # 14 days
JWT_SESSION_EXPIRE_SECONDS = 14 * 86400  # 14 days (0 disables session expiry)
JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS = 0  # required; positive values fail startup
JWT_LOGIN_THROTTLE_RATE = "5/min"  # None or "0" explicitly disables
JWT_REFRESH_THROTTLE_RATE = "30/min"
JWT_THROTTLE_CACHE_ALIAS = "default"
JWT_MAX_ACTIVE_SESSIONS = 20
JWT_TRUSTED_PROXY_CIDRS = []
JWT_PERSIST_CLIENT_IP = True
JWT_USER_LOGIN_AUTHENTICATOR = "jwt_ninja.authenticators.django_user_authenticator"
JWT_PAYLOAD_CLASS = "jwt_ninja.types.JWTPayload"
JWT_REFRESH_TOKEN_TRANSPORT = "body"  # "body", "cookie", or "both"
JWT_REFRESH_COOKIE_NAME = "refresh_token"
JWT_REFRESH_COOKIE_SECURE = True
JWT_REFRESH_COOKIE_HTTPONLY = True
JWT_REFRESH_COOKIE_SAMESITE = "Lax"  # "Lax", "Strict", or "None"
JWT_REFRESH_COOKIE_PATH = "/auth/refresh/"
JWT_REFRESH_COOKIE_DOMAIN = None
JWT_GEOLOCATION_PROVIDER = None  # Dotted path to a geolocation callable; None disables lookups
```

| Setting                              | Type                               | Description                                                                                     |
| ------------------------------------ | ---------------------------------- | ----------------------------------------------------------------------------------------------- |
| `JWT_SECRET_KEY`                     | `str`                              | Required dedicated signing key; never defaults to Django's `SECRET_KEY`. See [Signing key length](#signing-key-length). |
| `JWT_ALGORITHM`                      | `str`                              | PyJWT algorithm. Symmetric (`HS*`) or asymmetric (`RS*`, `ES*`, …). Validated at startup. `none` is rejected. Asymmetric algorithms require `pip install 'jwtninja[crypto]'`. |
| `JWT_ACCESS_TOKEN_EXPIRE_SECONDS`    | `int`                              | Lifetime of the short-lived access token.                                                      |
| `JWT_REFRESH_TOKEN_EXPIRE_SECONDS`   | `int`                              | Lifetime of the refresh token.                                                                 |
| `JWT_SESSION_EXPIRE_SECONDS`         | `int`                              | Hard max age applied to a `Session` at creation. `0` means sessions live until logged out.     |
| `JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS` | `int`                           | Must be `0`. Refresh tokens are strictly single-use. |
| `JWT_USER_LOGIN_AUTHENTICATOR`       | `str`                              | Dotted path to a callable `(request, payload) -> User \| None` used by `/auth/login/`.         |
| `JWT_PAYLOAD_CLASS`                  | `str`                              | Dotted path to a `JWTPayload` subclass if you need custom claims.                              |
| `JWT_REFRESH_TOKEN_TRANSPORT`        | `"body" \| "cookie" \| "both"` | Where refresh tokens are returned and read.                                                    |
| `JWT_REFRESH_COOKIE_NAME`            | `str`                              | Cookie name used when cookie transport is enabled.                                             |
| `JWT_REFRESH_COOKIE_SECURE`          | `bool`                             | Sets the cookie's `Secure` flag.                                                               |
| `JWT_REFRESH_COOKIE_HTTPONLY`        | `bool`                             | Sets the cookie's `HttpOnly` flag.                                                             |
| `JWT_REFRESH_COOKIE_SAMESITE`        | `"Lax" \| "Strict" \| "None"` | Sets the cookie's `SameSite` policy.                                                           |
| `JWT_REFRESH_COOKIE_PATH`            | `str`                              | Restricts the cookie to the refresh endpoint path.                                             |
| `JWT_REFRESH_COOKIE_DOMAIN`          | `str \| None`                     | Optional cookie domain override.                                                               |
| `JWT_GEOLOCATION_PROVIDER`           | `str \| None`                     | Dotted path to a callable `(ip: str) -> GeoLocation \| None` run once per login. `None` disables geolocation. See [Session geolocation](#session-geolocation). |

### Signing key length

For HMAC algorithms (the `HS*` family, including the default `HS256`), [RFC 7518 §3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2) requires the signing key to be at least the size of the hash output:

| Algorithm | Minimum key size |
| --------- | ---------------- |
| `HS256`   | 32 bytes         |
| `HS384`   | 48 bytes         |
| `HS512`   | 64 bytes         |

Shorter keys have less brute-force resistance than the JOSE profile requires. An attacker who recovers the key can forge tokens for any user. PEM, SSH, and JWK-looking asymmetric material is also rejected for HMAC profiles.

**JWT Ninja fails startup with `ImproperlyConfigured` if the configured key is too short.** RSA/PS keys below 2048 bits, public-only signing keys, mismatched key pairs, `none`, malformed keys, and incompatible algorithms also fail startup.

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

> **Security note:** Cookie and `both` modes enforce standard Django CSRF on login and refresh. Bootstrap with `GET /auth/csrf/`, retain the CSRF cookie, and send the returned masked token in `X-CSRFToken`. `SameSite="None"` is rejected unless both `Secure` and `HttpOnly` are enabled. Body mode does not require CSRF. Login and refresh accept only JSON media types (`application/json` or `application/*+json`).

## Refresh token rotation

Every call to `/auth/refresh/` mints a **new** refresh token and retires the one you presented. Each refresh token carries a `jti` claim, and the session row records the only `jti` it currently accepts.

The server treats a retired token as evidence that the token leaked, and **revokes the whole session**. The response is `401 token_reuse_detected`. This logs out the legitimate holder along with the attacker, which is the intended outcome once a token is known to be copied.

**What clients must do:** in `body` mode, persist the `refresh_token` from every `/auth/refresh/` response and send that one next time. Replaying a stored old token will log the user out. In `cookie` mode this is automatic, because the server sets a replacement cookie each time.

### Strict single use and ambiguous outcomes

There is no grace window. Rotation atomically consumes exactly the current `jti`; concurrent or replayed use revokes the whole session and returns `401 token_reuse_detected`. If a client loses a successful refresh response, it must **not retry the old token**: the outcome is ambiguous and retrying can revoke the winner's replacement token. Reauthenticate instead.

### Upgrading existing deployments

Legacy refresh tokens or session rows with a NULL `jti` are not adopted. The new `security_stamp` migration also intentionally invalidates every existing session row. Plan a forced reauthentication after migration.

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

> **Note:** The built-in issuer supplies only base claims. Extra fields therefore need defaults, or you must use a custom token-issuing/login flow that constructs them. A custom authenticator alone returns only a user and cannot inject required claims.

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

The session list, per-device sign-out, and geolocation are covered in [Device management](#device-management). The `Session` model also has helpers for common auth tasks.

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

> **On the recorded IP address:** `X-Forwarded-For` is ignored unless `REMOTE_ADDR` belongs to `JWT_TRUSTED_PROXY_CIDRS`. The full bounded chain is validated and scanned right-to-left across trusted proxies. Configure only CIDRs you operate. Set `JWT_PERSIST_CLIENT_IP=False` to avoid storing addresses.

A fixed-size HMAC fingerprint of `user.get_session_auth_hash()` is checked on every access and refresh. `set_password()`, bulk password-hash updates, NULL stamps, and callback failures therefore revoke the session without relying on signals; no raw historical password hash is stored.

## Deployment checklist

JWT Ninja applies default cache-backed limits of 5 login requests/minute and 30 refreshes/minute per trusted client identity, plus a 20-active-session cap that atomically revokes the oldest session. `JWT_THROTTLE_CACHE_ALIAS` selects the Django cache. LocMemCache counters are per process, so production deployments need a shared atomic cache and/or an edge limiter for a global guarantee. Tune or explicitly disable the throttles only after a deployment review.

- **Set request limits at the edge.** Cap request bodies and headers in the reverse proxy/Django server as well as using JWT Ninja's token, credential, forwarded-chain, and session-id bounds.
- **Schedule `Session.purge_expired_sessions()`.** Sessions carry a hard expiry, but nothing deletes the rows until you run the purge. See [Purge expired sessions](#purge-expired-sessions-eg-nightly-cron).
- **Serve over HTTPS.** Access tokens are bearer credentials. Anyone who observes one can use it until it expires.
- **Keep `JWT_ACCESS_TOKEN_EXPIRE_SECONDS` short.** Every request checks the access token against the DB session, so revocation is quick. A short lifetime is still your backstop.
- **Set a strong signing key.** See [Signing key length](#signing-key-length).
- **Size your geolocation provider to your login volume.** The built-in `ipapi_co_geolocator` does a blocking HTTPS lookup per login and is rate-limited. Beyond light traffic, switch to an offline database. See [Session geolocation](#session-geolocation).

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
