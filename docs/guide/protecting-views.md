---
icon: lucide/shield
---

# Protecting your views

Add `auth=JWTAuth()` to any Ninja route. Annotate the request as `AuthedRequest` to get typed access to the authenticated user and session:

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

!!! note "Access tokens only"

    `JWTAuth` requires `type == "access"`. A refresh token sent as a `Bearer` credential gets `401 invalid_token_type`.

## Per-session state

Each `Session` has a `JSONField` called `data`. Use it to store per-login state such as feature flags, device info, or an onboarding step:

```python
@router.post("/set-theme/", auth=JWTAuth())
def set_theme(request: AuthedRequest, theme: str):
    request.auth.session.data["theme"] = theme
    request.auth.session.save()
    return {"ok": True}
```
