![JWT Ninja Logo](https://github.com/user-attachments/assets/2589db23-94c7-47c6-8687-eb29c6312272) <br/>

# JWT Ninja

*A session‑backed, fully‑typed authentication library for **Django Ninja**, powered by **PyJWT***

[![PyPI](https://img.shields.io/pypi/v/jwtninja.svg)](https://pypi.python.org/pypi/jwtninja)
[![CI Status](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml/badge.svg)](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml)
[![License](https://img.shields.io/github/license/dvf/jwt-ninja)](LICENSE)

> **❤️ Contributions Welcome!**
> Feel free to submit a PR.
---

## 🚀 Quick Start

### Installation

JWT Ninja is a standard Django app. 

Install it with [uv](https://astral.sh/uv) or `pip`:

```bash
pip install jwtninja
```

Add it to **`INSTALLED_APPS`** in `settings.py`:

```python
INSTALLED_APPS = [
    ...,
    "jwt_ninja",
]
```

Lastly, don't forget to run migrations:

```bash
python manage.py migrate
```

### Usage

Register the built‑in router on your Ninja API:

```python
from ninja import NinjaAPI
from jwt_ninja.api import router as auth_router
from jwt_ninja.errors import APIError as AuthAPIError
from jwt_ninja.handlers import error_handler

api = NinjaAPI()
api.add_router("auth/", auth_router)

# Explicit control over how you went errors to be returned
api.add_exception_handler(AuthAPIError, error_handler)
```

Endpoints created:

| Method | Path                | Purpose                                         |
| ------ | ------------------- | ----------------------------------------------- |
| `POST` | `/auth/login/`      | Issue a new **access** & **refresh** token pair |
| `POST` | `/auth/refresh/`    | Refresh an access token                         |
| `GET`  | `/auth/sessions/`   | List active sessions                            |
| `POST` | `/auth/logout/`     | Log out of the current session                  |
| `POST` | `/auth/logout/all/` | Log out of **all** sessions                     |

Protect views with `JWTAuth` and enjoy typed requests:

```python
from ninja import Router
from jwt_ninja.auth_classes import JWTAuth, AuthedRequest


router = Router()

@router.get("/my-protected-endpoint/", auth=JWTAuth())
def my_protected_route(request: AuthedRequest):
    request.auth.session.data["foo"] = 123
    request.auth.session.save()  # Persist session changes
    return {"message": "Success!"}
```

---

## ⚙️ Default Settings

```python
# settings.py
JWT_SECRET_KEY = SECRET_KEY  # Django's Secret Key
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_SECONDS = 300          # 5 minutes
JWT_REFRESH_TOKEN_EXPIRE_SECONDS = 365 * 3600  # 1 year
JWT_SESSION_EXPIRE_SECONDS = 365 * 3600        # 1 year
JWT_USER_LOGIN_AUTHENTICATOR = "jwt_ninja.authenticators.django_user_authenticator"
JWT_PAYLOAD_CLASS = "jwt_ninja.types.JWTPayload"
```

### Custom Claims

If want additional data in the JWT payload, then you must subclass JWTPayload as below. 
```python
from jwt_ninja.types import JWTPayload


class CustomJWTPayload(JWTPayload):
    discord_user_id: str
    ip_address: str
    email: str
```

And then configure it:

```python
JWT_PAYLOAD_CLASS = "path.to.CustomJWTPayload"
```
