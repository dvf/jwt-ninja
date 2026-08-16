---
icon: lucide/rocket
---

# Getting started

JWT Ninja is a standard Django app. Install it, run migrations, and mount the router.

## Install

=== "uv"

    ```bash
    uv add jwtninja
    ```

=== "pip"

    ```bash
    pip install jwtninja
    ```

Requires Python **3.12+** and Django **5.x**.

!!! info "Asymmetric algorithms"

    Asymmetric signing algorithms (`RS*`, `ES*`, `PS*`, `EdDSA`) need PyJWT's cryptography extra:

    ```bash
    uv add "jwtninja[crypto]"
    # or
    pip install "jwtninja[crypto]"
    ```

## Quick start

**1.** Add `jwt_ninja` to your `INSTALLED_APPS`:

```python title="settings.py"
INSTALLED_APPS = [
    ...,
    "jwt_ninja",
]
```

**2.** Run migrations to create the `Session` table:

```bash
python manage.py migrate
```

**3.** Mount the router on your Ninja API and register the error handler:

```python title="api.py"
from ninja import NinjaAPI
from jwt_ninja import APIError
from jwt_ninja.api import router as auth_router
from jwt_ninja.handlers import error_handler

api = NinjaAPI()
api.add_router("auth/", auth_router)
api.add_exception_handler(APIError, error_handler)
```

This gives you `/auth/login/`, `/auth/refresh/`, `/auth/sessions/`, `/auth/sessions/{id}/`, `/auth/logout/`, and `/auth/logout/all/`.

## Next steps

- [Protect your views](protecting-views.md) with `JWTAuth`.
- Give users a session list with per-device sign-out: [Sessions & devices](sessions.md).
- Read the [endpoint reference](../reference/endpoints.md).
- Review the [configuration options](../reference/configuration.md).
- Before you go live, walk the [deployment checklist](deployment.md).
