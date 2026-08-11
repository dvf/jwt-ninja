import dataclasses

from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.utils import timezone
from ninja.security import HttpBearer

from . import settings as jwt_settings_module
from .cryptography import decode_jwt
from .errors import (
    APIError,
    JWTExpiredError,
    JWTInvalidPayloadFormat,
    JWTInvalidTokenError,
)
from .models import Session

User = get_user_model()


@dataclasses.dataclass
class AuthDetails:
    user: User
    session: Session


@dataclasses.dataclass
class AuthedRequest(HttpRequest):
    auth: AuthDetails


class JWTAuth(HttpBearer):
    def authenticate(self, request: HttpRequest, token: str) -> AuthDetails | None:
        try:
            payload = decode_jwt(token, jwt_settings_module.jwt_settings.payload_class)
        except JWTExpiredError:
            raise APIError("expired_token", 401)
        except (JWTInvalidPayloadFormat, JWTInvalidTokenError):
            raise APIError("invalid_token", 401)

        # Refresh tokens are long-lived and, under cookie transport, scoped to
        # the refresh endpoint. They must never authenticate a protected route.
        if payload.type != "access":
            raise APIError("invalid_token_type", 401)

        # Validate the Session
        try:
            session = Session.objects.get(id=payload.session_id)
        except Session.DoesNotExist:
            raise APIError("session_not_found", 401)
        if session.expired_at and session.expired_at < timezone.now():
            raise APIError("session_expired", 401)

        # The session and the user are named by two independent claims; a token
        # that pairs them differently than the DB does is not one we issued.
        if session.user_id != payload.user_id:
            raise APIError("invalid_token", 401)

        # Validate the user
        try:
            user = User.objects.get(id=payload.user_id, is_active=True)
        except User.DoesNotExist:
            raise APIError("invalid_user", 401)

        return AuthDetails(user=user, session=session)
