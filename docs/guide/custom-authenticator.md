---
icon: lucide/key-round
---

# Custom authenticator

If you do not use Django's `username`/`password` flow (SSO, magic links, OTP, etc.), point `JWT_USER_LOGIN_AUTHENTICATOR` at a callable that returns a `User` or `None`:

```python title="myapp/auth.py"
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.utils.timezone import now

User = get_user_model()


def magic_link_authenticator(request: HttpRequest, payload) -> User | None:
    try:
        return User.objects.get(magic_token=payload.token, magic_token_expired_at__gt=now())
    except User.DoesNotExist:
        return None
```

```python title="settings.py"
JWT_USER_LOGIN_AUTHENTICATOR = "myapp.auth.magic_link_authenticator"
```

The callable receives the raw `HttpRequest` and the parsed `LoginSchema` payload. If it returns `None`, the response is `401 invalid_credentials`.
