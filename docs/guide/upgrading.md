---
icon: lucide/arrow-up-circle
---

# Upgrading

This is an intentionally breaking, fail-closed security migration:

- Upgrade the runtime first: Python 3.12+ and Django >=5.2.16,<6.2 are required. Django 5.0 and 5.1 are no longer supported.
- Deploy atomically rather than running mixed old/new authentication workers. Old workers issue legacy-profile tokens that new workers reject; coordinate migration and replacement as a forced-reauthentication rollout.
- Configure an explicit dedicated `JWT_SECRET_KEY`, `JWT_ISSUER`, and `JWT_AUDIENCE` before startup. Django `SECRET_KEY` is no longer a fallback. Asymmetric algorithms require a separate matching `JWT_VERIFYING_KEY`.
- Short or incompatible JWT keys now stop startup instead of emitting `jwt_ninja.settings.InsecureJWTKeyWarning`; that warning class has been removed. Delete imports or warning filters that referenced it.
- Run `python manage.py migrate`. Migration 0004 expires all active pre-stamp rows; the nullable field also fails closed for restored/manual NULL rows. Plan a forced login for every user.
- Existing refresh tokens without a `jti` are rejected rather than adopted. `JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS` must be `0`; previous JTIs are never accepted.
- Refresh is strict single-use CAS rotation. A replay or concurrent consume commits family revocation and returns `token_reuse_detected`. A lost response is ambiguous and clients must reauthenticate rather than retry.
- Tokens now require validated issuer, audience, `iat`, `nbf`, `exp`, bounded lifetime, and exact JOSE `typ`. Old tokens without this profile are invalid.
- The default `JWT_REFRESH_TOKEN_EXPIRE_SECONDS` and `JWT_SESSION_EXPIRE_SECONDS` are now `14 * 86400` (14 days). The previous default read `365 * 3600` but evaluated to only ~15.2 days, so effective behavior is nearly unchanged; set the values explicitly if you relied on the old exact number.
- Cookie and both transport now enforce Django CSRF on both login and refresh. Add the `GET /auth/csrf/` bootstrap/header flow and send `{}` for cookie refresh.
- Login/refresh now require JSON media types and have default cache-backed limits (5/minute and 30/minute). The default user cap is 20 active sessions, revoking oldest first.
- Password authentication-hash changes revoke sessions on their next access or refresh, including bulk database updates without signals.
- `X-Forwarded-For` is ignored unless the direct peer is in `JWT_TRUSTED_PROXY_CIDRS`. Review IP persistence and geolocation consent/privacy settings.
- All auth responses are no-store. Apply deployment-level body and header size limits as an additional outer bound.

Read [Configuration](../reference/configuration.md), [Refresh tokens](refresh-tokens.md), and the [Deployment checklist](deployment.md) before rollout.
