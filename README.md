

![JWT Ninja Logo](https://github.com/user-attachments/assets/2589db23-94c7-47c6-8687-eb29c6312272)
<br/><br/>
A simple session-backed and fully-typed auth library for Django Ninja based on PyJWT. 
<br/><br/><br/>
[![image](https://img.shields.io/pypi/v/jwtninja.svg)](https://pypi.python.org/pypi/jwtninja)
[![Linting, Formatting and Tests](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml/badge.svg)](https://github.com/dvf/jwt-ninja/actions/workflows/check-and-test.yml)



# Installation
JWT Ninja is a Django app. Install it using [uv](https://astral.sh/uv) or `pip`:
```bash
pip install jwtninja
```

Then add it to your Django settings `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    ...
    "jwt_ninja"
]
```

# Usage

Import the router and register it to your Ninja API:
```python
from jwt_ninja.api import router as auth_router


api = NinjaAPI()

api.add_router("auth/", auth_router)
```

This will register the following endpoints:
- `/auth/login/` Create a new `access_token` and `refresh_token` pair
- `/auth/refresh/` Refresh a token
- `/auth/sessions/` List all your active sessions
- `/auth/logout/` Log out of your current session
- `/auth/logout/all/` Log out of all your sessions

Use the `JWTAuth` class to protect your views. You can use the `AuthedRequest` type to get annotations for the user and the session:

```python
from ninja import Router
from jwt_ninja.auth_classes import JWTAuth
from jwt_ninja.auth_classes import AuthedRequest

router = Router()

@router.get("/my_protected_endpoint/", auth=JWTAuth())
def my_protected_route(request: AuthedRequest):
    request.auth.session.data["foo"] = 123
    request.auth.session.save()  # Explicitly save the info for the user's session
    ...
```

# Customization and Configuration

JWT Ninja supports the following settings defined in your Django `settings.py`:

| Setting                            | Type | Default                                                |
|------------------------------------|------|--------------------------------------------------------|
| `JWT_SECRET_KEY`                   | str  | django_settings.SECRET_KEY                             |
| `JWT_ALGORITHM`                    | str  | `"HS256"`                                              |
| `JWT_ACCESS_TOKEN_EXPIRE_SECONDS`  | int  | `300` (5 minutes)                                      |
| `JWT_REFRESH_TOKEN_EXPIRE_SECONDS` | int  | `365 * 3600` (1 year)                                  |
| `JWT_SESSION_EXPIRE_SECONDS`       | int  | `365 * 3600` (1 year)                                  |
| `JWT_USER_LOGIN_AUTHENTICATOR`     | str  | `"jwt_ninja.authenticators.django_user_authenticator"` |
| `JWT_PAYLOAD_CLASS`                | str  | `"jwt_ninja.types.JWTPayload"`                         |

## Custom Claims

Subclass `jwt_ninja.types.JWTPayload` with any additional claims:

```python
from jwt_ninja.types import JWTPayload


class CustomJWTPayload(JWTPayload):
    discord_user_id: str
    ip_address: str
    email: str
```

Then add `JWT_PAYLOAD_CLASS = "path.to.your.CustomJWTPayload` to your `settings.py`.
