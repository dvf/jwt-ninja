---
icon: lucide/house
hide:
  - navigation
---

![JWT Ninja](assets/logo-light.png#only-light){ width="340" }
![JWT Ninja](assets/logo-dark.png#only-dark){ width="340" }

*A session-backed, fully-typed authentication library for **[Django Ninja](https://django-ninja.dev/)**, powered by **[PyJWT](https://pyjwt.readthedocs.io/)**.*

[![PyPI](https://img.shields.io/pypi/v/jwtninja.svg)](https://pypi.python.org/pypi/jwtninja)
[![CI Status](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml/badge.svg)](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml)
[![License](https://img.shields.io/github/license/dvf/jwt-ninja)](https://github.com/dvf/jwt-ninja/blob/master/LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)

<div class="grid cards" markdown>

-   :lucide-database:{ .lg .middle } **Stateful JWTs**

    ---

    Every token maps to a `Session` row in the database. You get token-based auth plus revocation, device listing, and per-session state.

-   :lucide-braces:{ .lg .middle } **Fully typed**

    ---

    Protected routes receive an `AuthedRequest` with typed `request.auth.user` and `request.auth.session`. OpenAPI schemas include typed error responses.

-   :lucide-cookie:{ .lg .middle } **Three refresh-token transports**

    ---

    JSON body, HttpOnly cookie, or both. Refresh tokens rotate on every use.

-   :lucide-package-check:{ .lg .middle } **Complete**

    ---

    Five auth endpoints, a Django admin page, a pluggable payload class for custom claims, and a pluggable authenticator for non-password login flows.

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

[Get started](guide/getting-started.md){ .md-button .md-button--primary }
[Endpoint reference](reference/endpoints.md){ .md-button }
