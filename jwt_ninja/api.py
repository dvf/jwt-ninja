import time
from typing import Any, Literal

from django.http import HttpRequest
from django.utils import timezone
from django.utils.module_loading import import_string
from ninja import Router

from .auth_classes import AuthedRequest, JWTAuth, User
from .cryptography import decode_jwt, generate_jwt
from .errors import (
    APIError,
    JWTExpiredError,
    JWTInvalidPayloadFormat,
    JWTInvalidTokenError,
)
from .models import Session
from .request import get_client_ip
from .settings import jwt_settings
from .types import (
    AccessTokenSchema,
    ErrorResponseType,
    JWTPayload,
    LoginSchema,
    RefreshTokenSchema,
    SessionResponse,
    TokenSchema,
)

router = Router(tags=["Authentication"])


@router.post(
    "login/",
    summary="Obtain a new access token",
    description="Supply a valid `username` and `password` to obtain a new `access_token` and `refresh_token`.",
    response={
        200: TokenSchema,
        401: ErrorResponseType[Literal["invalid_credentials"]],
    },
    auth=None,
)
def login(request: HttpRequest, payload: LoginSchema) -> TokenSchema:
    user = import_string(jwt_settings.USER_LOGIN_AUTHENTICATOR)(request, payload)

    if not user:
        raise APIError("invalid_credentials", 401)

    # Create a new DB-backed session for the User
    session = Session.create_session(
        user=user,
        ip_address=get_client_ip(request),
    )

    current_timestamp = int(time.time())
    access_payload = JWTPayload(
        user_id=user.id,
        type="access",
        # RFC 7519 says that the exp must be a NumericDate
        # see https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
        exp=current_timestamp + jwt_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
        session_id=session.id,
    )
    access_token = generate_jwt(access_payload)

    refresh_payload = JWTPayload(
        user_id=user.id,
        exp=current_timestamp + jwt_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
        type="refresh",
        session_id=session.id,
    )
    refresh_token = generate_jwt(refresh_payload)

    return TokenSchema(access_token=access_token, refresh_token=refresh_token)


@router.post(
    "refresh/",
    summary="Refresh an access token",
    description="Supply a valid, unexpired `refresh_token` to obtain a new `access_token`.",
    response={
        200: AccessTokenSchema,
        400: ErrorResponseType[Literal["invalid_token_type"]],
        401: ErrorResponseType[
            Literal[
                "token_expired",
                "invalid_token",
                "invalid_user",
            ]
        ],
    },
    auth=None,
)
def new_refresh_token(request: HttpRequest, payload: RefreshTokenSchema) -> Any:
    try:
        refresh_payload = decode_jwt(payload.refresh_token, JWTPayload)
    except JWTExpiredError:
        raise APIError("expired_token", http_status_code=401)
    except (JWTInvalidTokenError, JWTInvalidPayloadFormat):
        raise APIError("invalid_token", http_status_code=401)

    if refresh_payload.type != "refresh":
        raise APIError("invalid_token_type", http_status_code=400)

    try:
        user = User.objects.get(id=refresh_payload.user_id, is_active=True)
    except User.DoesNotExist:
        raise APIError("invalid_user", http_status_code=401)

    current_timestamp = int(time.time())
    access_payload = JWTPayload(
        user_id=user.id,
        exp=current_timestamp + jwt_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
        type="access",
        session_id=refresh_payload.session_id,
    )
    try:
        access_token = generate_jwt(access_payload)
    except (JWTExpiredError, JWTInvalidTokenError, JWTInvalidPayloadFormat):
        raise APIError("invalid_token", http_status_code=401)

    return AccessTokenSchema(access_token=access_token)


@router.get(
    "sessions/",
    summary="List active sessions",
    response={200: list[SessionResponse]},
    auth=JWTAuth(),
)
def list_active_sessions(request: AuthedRequest):
    return request.auth.user.jwt_sessions.filter(expired_at__isnull=True)


@router.post(
    "logout/",
    summary="Logout",
    description="Log out of the current session.",
    response={200: None},
    auth=JWTAuth(),
)
def logout(request: AuthedRequest):
    request.auth.session.expired_at = timezone.now()
    request.auth.session.save()
    return None


@router.post(
    "logout/all/",
    summary="Logout from all sessions",
    description="Log out of all sessions.",
    response={200: None},
    auth=JWTAuth(),
)
def logout_all(request: AuthedRequest):
    # Sign out all active sessions
    Session.objects.filter(
        user_id=request.auth.user.id,
        expired_at__isnull=True,
    ).update(
        expired_at=timezone.now(),
    )
    return None
