from typing import Any

from django.contrib.auth import authenticate
from django.contrib.auth.models import AbstractBaseUser
from django.http import HttpRequest


def django_user_authenticator(request: HttpRequest, payload: Any) -> AbstractBaseUser | None:
    return authenticate(
        request=request,
        username=payload.username,
        password=payload.password,
    )
