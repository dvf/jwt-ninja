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

    The built-in issuer supplies only base claims. Extra fields need defaults, or a custom token-issuing/login flow must construct them. A [custom authenticator](custom-authenticator.md) alone returns only a user and cannot inject required claims.

## Non-integer user ids

If your User model has an integer or string primary key (`AutoField`, `CharField`, a prefixed id), there is nothing to do: `JWTPayload` declares `user_id: int | str | UUID`, and both kinds come back from a token as they went in. An integer stays an integer and a string stays a string, so `"5"` never matches the user with id `5`.

A `UUIDField` key needs one line. JSON has no UUID type, so the claim travels as text and decodes as `str` unless you narrow the field:

```python
from uuid import UUID
from jwt_ninja import JWTPayload


class UUIDJWTPayload(JWTPayload):
    user_id: UUID
```

You may narrow it for the other kinds too (`user_id: str`) to give your own code a precise type. Be aware that a type checker which treats model fields as read-write (pyrefly, for one) reports any narrowed override, the `UUID` one included, because a subclass may not change the type of a writable attribute. Suppress that line, or keep the stock type and convert where you use the value (`str(payload.user_id)`).
