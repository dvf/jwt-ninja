---
icon: lucide/file-json
---

# Custom claims

To embed extra data in the token itself (team id, feature flags, etc.), subclass `JWTPayload` and point `JWT_PAYLOAD_CLASS` at it. Encode and decode sites both use the configured class, so your custom fields round-trip end to end.

```python title="myapp/auth.py"
from jwt_ninja import JWTPayload


class CustomJWTPayload(JWTPayload):
    team_id: int
    email: str
```

```python title="settings.py"
JWT_PAYLOAD_CLASS = "myapp.auth.CustomJWTPayload"
```

!!! note

    If you add required fields, you also need a [custom authenticator](custom-authenticator.md) or a custom login endpoint that populates them.

## Overriding `user_id`

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
