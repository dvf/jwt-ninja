---
icon: lucide/server
---

# Deployment checklist

JWT Ninja deliberately leaves these tasks to your application:

- [ ] **Rate-limit `/auth/login/`.** Nothing in JWT Ninja throttles password guessing. Put a throttle in front of the endpoint: Django Ninja's built-in throttling, `django-ratelimit`, or your reverse proxy or WAF. Consider a rate limit on `/auth/refresh/` too.
- [ ] **Schedule `Session.purge_expired_sessions()`.** Sessions carry a hard expiry, but nothing deletes the rows until you run the purge. See [Purge expired sessions](sessions.md#purge-expired-sessions).
- [ ] **Serve over HTTPS.** Access tokens are bearer credentials. Anyone who observes one can use it until it expires.
- [ ] **Keep `JWT_ACCESS_TOKEN_EXPIRE_SECONDS` short.** Every request checks the access token against the DB session, so revocation is quick. A short lifetime is still your backstop.
- [ ] **Set a strong signing key.** See [Signing key length](../reference/configuration.md#signing-key-length).
- [ ] **Size your geolocation provider to your login volume.** The built-in `ipapi_co_geolocator` does a blocking HTTPS lookup per login and is rate-limited. Beyond light traffic, switch to an offline database. See [Session geolocation](sessions.md#session-geolocation).
