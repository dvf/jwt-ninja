---
icon: lucide/arrow-up-circle
---

# Upgrading

This release tightens several auth behaviors. Read these notes before you upgrade an existing deployment.

- **Refresh tokens no longer authenticate protected routes.** `JWTAuth` now requires `type == "access"`. Any other token type gets `401 invalid_token_type`. If a client sends its refresh token as a `Bearer` credential, it must switch to the access token.
- **Refresh tokens rotate on every use.** `/auth/refresh/` now returns a new `refresh_token` with the access token and retires the one you sent. Clients in `body` mode must store and use the returned token. Clients in `cookie` mode need no change. See [Rotation](refresh-tokens.md#rotation).
- **`/auth/refresh/` now validates the session.** If the session was logged out or deleted, the server rejects the refresh token instead of minting a new access token.
- **Sessions now have a hard expiry.** Earlier versions ignored `JWT_SESSION_EXPIRE_SECONDS`, so sessions never expired. The setting now applies at session creation. Set it to `0` to keep the old behavior.
- **`expired_at` is set on live sessions.** `expired_at__isnull=True` no longer means "active". Use `Session.objects.active()` in your own queries.
- **Deleting a `User` now returns `session_not_found` on `/auth/refresh/`, not `invalid_user`.** The delete cascade removes the session first. Both codes are `401`.
- **`JWT_ALGORITHM` is validated at startup.** `none`, typos, and asymmetric algorithms without the `crypto` extra now raise `ImproperlyConfigured` instead of failing later.

Run `python manage.py migrate` to add the rotation columns.

!!! tip "Existing refresh tokens survive the upgrade"

    Refresh tokens issued before rotation existed are accepted once and adopted into rotation, so upgrading does not log out your user base. See [Upgrading existing deployments](refresh-tokens.md#upgrading-existing-deployments).
