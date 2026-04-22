import time
from typing import Any, Literal

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.utils.module_loading import import_string
from ninja import Router

from . import settings as jwt_settings_module
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
from .types import (
    AccessTokenSchema,
    ErrorResponseType,
    LoginSchema,
    RefreshTokenSchema,
    SessionResponse,
    TokenSchema,
)

router = Router(tags=["Authentication"])


def _set_refresh_cookie(response: HttpResponse, refresh_token: str) -> None:
    response.set_cookie(
        key=jwt_settings_module.jwt_settings.REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=jwt_settings_module.jwt_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
        path=jwt_settings_module.jwt_settings.REFRESH_COOKIE_PATH,
        domain=jwt_settings_module.jwt_settings.REFRESH_COOKIE_DOMAIN,
        secure=jwt_settings_module.jwt_settings.REFRESH_COOKIE_SECURE,
        httponly=jwt_settings_module.jwt_settings.REFRESH_COOKIE_HTTPONLY,
        samesite=jwt_settings_module.jwt_settings.REFRESH_COOKIE_SAMESITE,
    )


def _delete_refresh_cookie(response: HttpResponse) -> None:
    response.delete_cookie(
        key=jwt_settings_module.jwt_settings.REFRESH_COOKIE_NAME,
        path=jwt_settings_module.jwt_settings.REFRESH_COOKIE_PATH,
        domain=jwt_settings_module.jwt_settings.REFRESH_COOKIE_DOMAIN,
        samesite=jwt_settings_module.jwt_settings.REFRESH_COOKIE_SAMESITE,
    )


def _build_login_response(access_token: str, refresh_token: str) -> JsonResponse:
    response_payload: dict[str, str] = {"access_token": access_token}

    if jwt_settings_module.jwt_settings.REFRESH_TOKEN_TRANSPORT in {"body", "both"}:
        response_payload["refresh_token"] = refresh_token

    response = JsonResponse(response_payload)

    if jwt_settings_module.jwt_settings.REFRESH_TOKEN_TRANSPORT in {"cookie", "both"}:
        _set_refresh_cookie(response, refresh_token)

    return response


def _get_refresh_token(request: HttpRequest, payload: RefreshTokenSchema | None) -> str:
    body_refresh_token = payload.refresh_token if payload else None

    if jwt_settings_module.jwt_settings.REFRESH_TOKEN_TRANSPORT == "body":
        refresh_token = body_refresh_token
    elif jwt_settings_module.jwt_settings.REFRESH_TOKEN_TRANSPORT == "cookie":
        refresh_token = request.COOKIES.get(jwt_settings_module.jwt_settings.REFRESH_COOKIE_NAME)
    else:
        refresh_token = body_refresh_token or request.COOKIES.get(jwt_settings_module.jwt_settings.REFRESH_COOKIE_NAME)

    if not refresh_token:
        raise APIError("invalid_token", http_status_code=401)

    return refresh_token


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
def login(request: HttpRequest, payload: LoginSchema) -> HttpResponse:
    user = import_string(jwt_settings_module.jwt_settings.USER_LOGIN_AUTHENTICATOR)(request, payload)

    if not user:
        raise APIError("invalid_credentials", 401)

    # Create a new DB-backed session for the User
    session = Session.create_session(
        user=user,
        ip_address=get_client_ip(request),
    )

    current_timestamp = int(time.time())
    access_payload = jwt_settings_module.jwt_settings.payload_class(
        user_id=user.id,
        type="access",
        # RFC 7519 says that the exp must be a NumericDate
        # see https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
        exp=current_timestamp + jwt_settings_module.jwt_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
        session_id=session.id,
    )
    access_token = generate_jwt(access_payload)

    refresh_payload = jwt_settings_module.jwt_settings.payload_class(
        user_id=user.id,
        exp=current_timestamp + jwt_settings_module.jwt_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
        type="refresh",
        session_id=session.id,
    )
    refresh_token = generate_jwt(refresh_payload)

    return _build_login_response(access_token=access_token, refresh_token=refresh_token)


@router.post(
    "refresh/",
    summary="Refresh an access token",
    description="Supply a valid, unexpired `refresh_token` to obtain a new `access_token`.",
    response={
        200: AccessTokenSchema,
        400: ErrorResponseType[Literal["invalid_token_type"]],
        401: ErrorResponseType[
            Literal[
                "expired_token",
                "invalid_token",
                "invalid_user",
            ]
        ],
    },
    auth=None,
)
def new_refresh_token(request: HttpRequest, payload: RefreshTokenSchema | None = None) -> Any:
    refresh_token = _get_refresh_token(request, payload)

    try:
        refresh_payload = decode_jwt(refresh_token, jwt_settings_module.jwt_settings.payload_class)
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
    access_payload = jwt_settings_module.jwt_settings.payload_class(
        user_id=user.id,
        exp=current_timestamp + jwt_settings_module.jwt_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
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
def logout(request: AuthedRequest) -> HttpResponse:
    request.auth.session.expired_at = timezone.now()
    request.auth.session.save()

    response = HttpResponse(status=200)
    if jwt_settings_module.jwt_settings.REFRESH_TOKEN_TRANSPORT in {"cookie", "both"}:
        _delete_refresh_cookie(response)
    return response


@router.post(
    "logout/all/",
    summary="Logout from all sessions",
    description="Log out of all sessions.",
    response={200: None},
    auth=JWTAuth(),
)
def logout_all(request: AuthedRequest) -> HttpResponse:
    # Sign out all active sessions
    Session.objects.filter(
        user_id=request.auth.user.id,
        expired_at__isnull=True,
    ).update(
        expired_at=timezone.now(),
    )

    response = HttpResponse(status=200)
    if jwt_settings_module.jwt_settings.REFRESH_TOKEN_TRANSPORT in {"cookie", "both"}:
        _delete_refresh_cookie(response)
    return response
