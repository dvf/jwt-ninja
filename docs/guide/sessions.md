---
icon: lucide/monitor-smartphone
---

# Session management

The `Session` model has helpers for common auth tasks.

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

!!! warning "On the recorded IP address"

    `Session.ip_address` prefers the first entry in `X-Forwarded-For` and falls back to `REMOTE_ADDR`. Non-IP values are discarded rather than stored. Any client can send `X-Forwarded-For`, so the value is only trustworthy if a proxy you control overwrites the header on the way in. Treat it as a hint for support and debugging, not as evidence in an investigation.
