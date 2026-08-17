---
icon: lucide/refresh-cw
---

# Refresh tokens

## Transport and browser CSRF

- **`body`** (default): login returns the refresh token and refresh accepts it in JSON. CSRF is not required.
- **`cookie`**: the token is an HttpOnly cookie. Login and refresh require standard Django CSRF validation.
- **`both`**: the token is returned both ways. CSRF is still mandatory; supplying a body token does not bypass it.

Login and refresh accept only `application/json` (parameters allowed) or `application/*+json`. Form, `text/plain`, and missing content types return `415 unsupported_media_type` before body parsing. Cookie refresh clients must send `{}` as the JSON body.

Browser flow:

1. `GET /auth/csrf/`; retain the Django CSRF cookie and read `csrf_token` from the response.
2. Send that masked value in `X-CSRFToken` on `POST /auth/login/` and `POST /auth/refresh/`.
3. Continue sending credentials/cookies according to the selected transport.

Django's trusted-origin and HTTPS CSRF rules apply. `SameSite=None` is rejected unless refresh cookies are both Secure and HttpOnly.

## Strict atomic rotation

Every refresh token has a `jti`. A refresh atomically changes the same session row only when the session id, user id, live expiry, security stamp, and exact current `jti` all match. There is no grace window and `JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS` must be `0`. Previous JTIs are never authorized.

A concurrent consume or replay returns `401 token_reuse_detected` and revokes the entire token family. Revocation commits before the error is raised. Consequently, even a replacement token returned to a race winner becomes unusable after the replay is detected.

!!! warning "Ambiguous refresh outcome"

    If the connection drops after sending a refresh, do not retry the old token. The server may have consumed it successfully; retrying can revoke the session. Discard the uncertain token state and require reauthentication.

Legacy NULL-JTI tokens are not adopted. Migration to the security-stamped session model intentionally requires all existing users to authenticate again.

Refresh is limited to 30 requests/minute per trusted client identity by default and is denied before decode when over limit. Tune with `JWT_REFRESH_THROTTLE_RATE`.
