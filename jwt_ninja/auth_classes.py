import dataclasses

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import DataError
from django.http import HttpRequest
from django.utils import timezone
from ninja.security import HttpBearer

from . import settings as jwt_settings_module
from .cryptography import decode_jwt
from .errors import APIError, JWTExpiredError, JWTInvalidPayloadFormat, JWTInvalidTokenError
from .models import Session

User = get_user_model()
_SESSION_ID_MAX_LENGTH = 43


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

        if payload.type != "access":
            raise APIError("invalid_token_type", 401)
        if not payload.session_id or len(payload.session_id) > _SESSION_ID_MAX_LENGTH:
            raise APIError("invalid_token", 401)

        try:
            session = Session.objects.get(id=payload.session_id)
        except Session.DoesNotExist:
            raise APIError("session_not_found", 401)
        except (ValidationError, DataError, TypeError, ValueError):
            raise APIError("invalid_token", 401)
        if session.expired_at is not None and session.expired_at <= timezone.now():
            raise APIError("session_expired", 401)
        if session.user_id != payload.user_id:
            raise APIError("invalid_token", 401)

        try:
            user = User.objects.get(id=payload.user_id, is_active=True)
        except User.DoesNotExist:
            raise APIError("invalid_user", 401)
        except (ValidationError, DataError, TypeError, ValueError):
            raise APIError("invalid_token", 401)

        if not session.security_stamp_matches(user):
            raise APIError("session_expired", 401)
        return AuthDetails(user=user, session=session)
