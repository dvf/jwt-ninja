---
icon: lucide/house
hide:
  - navigation
---

# ![JWT Ninja](assets/logo-light.png#only-light){ width="340" }![JWT Ninja](assets/logo-dark.png#only-dark){ width="340" }

*A session-backed, fully-typed authentication library for **[Django Ninja](https://django-ninja.dev/)**, powered by **[PyJWT](https://pyjwt.readthedocs.io/)**.*

[![PyPI](https://img.shields.io/pypi/v/jwtninja.svg)](https://pypi.python.org/pypi/jwtninja)
[![CI Status](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml/badge.svg)](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml)
[![License](https://img.shields.io/github/license/dvf/jwt-ninja)](https://github.com/dvf/jwt-ninja/blob/master/LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)

<div class="grid cards" markdown>

-   :lucide-database:{ .lg .middle } **Stateful JWTs**

    ---

    Every token maps to a `Session` row in the database. You get token-based auth plus instant revocation and per-session state.

-   :lucide-monitor-smartphone:{ .lg .middle } **Built-in device management**

    ---

    Each user gets a session list with IP address, browser, and location. Users can sign out one device or all devices. Geolocation providers are pluggable, and a free one is included.

-   :lucide-braces:{ .lg .middle } **Fully typed**

    ---

    Protected routes receive an `AuthedRequest` with typed `request.auth.user` and `request.auth.session`. OpenAPI schemas include typed error responses.

-   :lucide-cookie:{ .lg .middle } **Three refresh-token transports**

    ---

    JSON body, HttpOnly cookie, or both. Refresh tokens rotate on every use.

-   :lucide-package-check:{ .lg .middle } **Complete**

    ---

    Six auth endpoints, a Django admin page, a pluggable payload class for custom claims, a pluggable authenticator for non-password login flows, and a pluggable geolocation provider for the session list.

</div>

## At a glance

Protect a route and get typed access to the user and session:

```python
from ninja import Router
from jwt_ninja import AuthedRequest, JWTAuth

router = Router()


@router.get("/profile/", auth=JWTAuth())
def profile(request: AuthedRequest):
    user = request.auth.user  # the Django User
    session = request.auth.session  # the jwt_ninja Session
    return {"username": user.username, "session_id": session.id}
```

Give every user a "where am I signed in?" screen with `GET /auth/sessions/`:

```json
[
  {
    "id": "8dKt2…",
    "ip_address": "203.0.113.42",
    "browser": "Chrome on macOS",
    "location": { "city": "Amsterdam", "country": "Netherlands" },
    "is_current": true
  }
]
```

Users sign out one device with `DELETE /auth/sessions/{id}/`, or all devices with `POST /auth/logout/all/`.

[Get started](guide/getting-started.md){ .md-button .md-button--primary }
[Sessions & devices](guide/sessions.md){ .md-button }
[Endpoint reference](reference/endpoints.md){ .md-button }
