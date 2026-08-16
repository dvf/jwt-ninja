---
icon: lucide/monitor-smartphone
---

# Sessions & devices

Most JWT libraries stop after they issue a token. Because every JWT Ninja token maps to a database session, your users get the "where am I signed in?" screen they know from Google or GitHub. This page covers the session list, per-device sign-out, and geolocation.

## The session list

`GET /auth/sessions/` returns one row for each logged-in device. Each row shows the login IP address, the raw and summarized user agent, an optional location, and an `is_current` marker. See the [endpoint reference](../reference/endpoints.md#get-authsessions) for the full payload.

JWT Ninja records the `User-Agent` header and the client IP one time, at login. The `browser` field is a summary of the recorded header, for example "Chrome on macOS". JWT Ninja parses it in-process, with no added dependency and no lookup.

Users can sign out of one session, or of all sessions at once:

- `DELETE /auth/sessions/{id}/` revokes one session ("sign out that device"). If the id is not one of the caller's own active sessions, the response is `404 session_not_found`.
- `POST /auth/logout/all/` revokes every session the user has.

When JWT Ninja revokes a session, it sets `expired_at` on the row. This immediately stops the session's access tokens, which are checked on every request. It also stops the session's refresh tokens, which are checked on every refresh.

!!! warning "On the recorded IP address"

    `Session.ip_address` prefers the first entry in `X-Forwarded-For` and falls back to `REMOTE_ADDR`. Non-IP values are discarded rather than stored. Any client can send `X-Forwarded-For`, so the value is only trustworthy if a proxy you control overwrites the header on the way in. Treat it as a hint for support and debugging, not as evidence in an investigation.

## Session geolocation

Geolocation is off by default. To fill the `location` field, point `JWT_GEOLOCATION_PROVIDER` at a callable. JWT Ninja includes a free provider backed by [ipapi.co](https://ipapi.co) — HTTPS, no API key, approximately 1,000 lookups per day:

```python title="settings.py"
JWT_GEOLOCATION_PROVIDER = "jwt_ninja.geolocation.ipapi_co_geolocator"
```

The provider runs one time per login, and JWT Ninja stores the result on the session's `location` field. The list endpoint reads the stored value and does no lookups. If the provider fails, JWT Ninja logs the error and completes the login without a location. JWT Ninja does not send private, loopback, or other non-routable addresses to the provider.

### Writing your own provider

Any callable `(ip: str) -> GeoLocation | None` works. An offline database avoids the per-login HTTP round-trip and third-party rate limits:

```python title="myapp/geo.py"
# Offline lookups via MaxMind GeoLite2 and Django's GeoIP2
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

```python title="settings.py"
JWT_GEOLOCATION_PROVIDER = "myapp.geo.geoip2_geolocator"
```

Every `GeoLocation` field is optional. Set the fields that your source can resolve. If your provider raises an error, JWT Ninja logs it and completes the login without a location. Prefer to return `None` for an address that you cannot resolve.

!!! warning "Privacy"

    An HTTP provider sends your users' IP addresses to a third party at each login. If this conflicts with your privacy or compliance requirements, use an offline database or keep geolocation off.

## Invalidate all sessions

On a password change, log the user out of every device:

```python
from jwt_ninja.models import Session

Session.invalidate_all_user_sessions(user)
```

This runs one bulk `UPDATE` that sets `expired_at` on every active session for the user.

## Purge expired sessions

Over time, rows accumulate for sessions long past their `expired_at`. Delete them with a scheduled task:

```python
from jwt_ninja.models import Session

# Run from django-crontab, Celery beat, or a management command
Session.purge_expired_sessions()
```

## Inspect sessions in the admin

`jwt_ninja` registers a read-only `SessionAdmin` at `/admin/jwt_ninja/session/`. Use it to see which users are logged in, and from where.
