---
icon: lucide/refresh-cw
---

# Refresh tokens

JWT Ninja delivers refresh tokens over three transports and rotates them on every use.

## Transport

Set `JWT_REFRESH_TOKEN_TRANSPORT` to one of three modes:

- **`"body"`** *(default)* — `login/` returns `refresh_token` in JSON, and `refresh/` expects it in the request body.
- **`"cookie"`** — `login/` sets the refresh token in an **HttpOnly cookie**, and `refresh/` reads it from that cookie.
- **`"both"`** — `login/` returns the refresh token in JSON **and** sets the cookie. `refresh/` accepts either the request body or the cookie.

Example browser-oriented configuration:

```python title="settings.py"
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

!!! warning "Security note"

    HttpOnly cookies reduce refresh-token exposure to JavaScript, but cookie-based auth flows are still subject to CSRF considerations. For browser deployments, prefer `Secure=True`, keep refresh endpoints as `POST`, and choose a `SameSite` policy that fits your application. `SameSite="None"` removes the browser's cross-site protection on the refresh endpoint. If you set it, add your own CSRF defense.

## Rotation

Every call to `/auth/refresh/` mints a **new** refresh token and retires the one you presented. Each refresh token carries a `jti` claim, and the session row records the only `jti` it currently accepts.

The server treats a retired token as evidence that the token leaked, and **revokes the whole session**. The response is `401 token_reuse_detected`. This logs out the legitimate holder along with the attacker, which is the intended outcome once a token is known to be copied.

!!! tip "What clients must do"

    In `body` mode, persist the `refresh_token` from every `/auth/refresh/` response and send that one next time. Replaying a stored old token will log the user out. In `cookie` mode this is automatic, because the server sets a replacement cookie each time.

### The grace window

A dropped connection can lose the refresh response. The client then retries with a token the server has already rotated past. To keep that retry from revoking a real session, the previous token stays valid for `JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS` (default `30`) after rotation.

Set it to `0` for strict single-use tokens. That choice logs out users whose refresh request gets retried.

### Upgrading existing deployments

Refresh tokens issued before rotation existed carry no `jti`, and their sessions have no recorded `jti` either. The server accepts such a token **once** and adopts the session into rotation, so upgrading does not log out your whole user base. After that first use, the old token is retired like any other.
