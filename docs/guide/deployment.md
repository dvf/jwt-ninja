---
icon: lucide/server
---

# Deployment checklist

- [ ] Configure a dedicated `JWT_SECRET_KEY`, explicit `JWT_ISSUER` and `JWT_AUDIENCE`; configure a separate public `JWT_VERIFYING_KEY` for asymmetric signing.
- [ ] Run migrations and plan forced reauthentication. Migration 0004 expires active pre-stamp rows; restored/manual NULL stamps also fail closed.
- [ ] Serve over HTTPS. Keep access lifetimes short and clocks synchronized.
- [ ] Confirm Django's CSRF middleware/settings, trusted origins, cookie domain, and browser flow for `cookie`/`both` transport. Bootstrap via `GET /auth/csrf/`.
- [ ] Configure `JWT_TRUSTED_PROXY_CIDRS` only for proxies that overwrite forwarded headers. Leave it empty when Django is directly exposed.
- [ ] Review default throttles (login 5/minute, refresh 30/minute), cache availability/capacity, and the 20-active-session cap. Cache failure denies login/refresh. LocMemCache is per process; use `JWT_THROTTLE_CACHE_ALIAS` for a shared atomic cache and/or an edge limiter.
- [ ] Apply reverse-proxy/application limits for body and header sizes. JWT Ninja bounds credentials, tokens, session ids, user agents, and forwarded chains, but the edge should reject oversized requests before Django allocates them.
- [ ] Schedule `Session.purge_expired_sessions()`.
- [ ] Decide whether IP persistence is necessary (`JWT_PERSIST_CLIENT_IP=False` disables it).
- [ ] Keep geolocation off unless needed. For the built-in third-party provider, record privacy/legal approval and set explicit consent; configure timeout/response limits. Prefer an offline provider.
- [ ] Test password changes. A fixed-size HMAC fingerprint of `get_session_auth_hash()` is checked on every access and refresh, so `set_password()` and bulk password-hash changes revoke sessions without signals.

PostgreSQL is the production concurrency target. SQLite receives bounded lock retries but is not recommended for concurrent authentication workloads.

All auth-router responses, including controlled errors, are marked `Cache-Control: no-store` and `Pragma: no-cache`.
