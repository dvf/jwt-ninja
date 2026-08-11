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


def _issue_token_pair(user: User, session: Session) -> tuple[str, str]:
    """
    Mint an access/refresh pair bound to `session`, rotating its refresh token id.

    Rotating here means the refresh token handed out by the previous call stops
    being accepted once the grace window closes, so a leaked token has a short
    useful life and its replay is detectable.
    """
    jti = session.rotate_refresh_jti()
    current_timestamp = int(time.time())

    access_payload = jwt_settings_module.jwt_settings.payload_class(
        user_id=user.id,
        type="access",
        # RFC 7519 says that the exp must be a NumericDate
        # see https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
        exp=current_timestamp + jwt_settings_module.jwt_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
        session_id=session.id,
    )
    refresh_payload = jwt_settings_module.jwt_settings.payload_class(
        user_id=user.id,
        type="refresh",
        exp=current_timestamp + jwt_settings_module.jwt_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
        session_id=session.id,
        jti=jti,
    )
    return generate_jwt(access_payload), generate_jwt(refresh_payload)


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

    access_token, refresh_token = _issue_token_pair(user, session)

    return _build_login_response(access_token=access_token, refresh_token=refresh_token)


@router.post(
    "refresh/",
    summary="Refresh an access token",
    description="Supply a valid, unexpired `refresh_token` to obtain a new `access_token`.",
    response={
        200: TokenSchema,
        400: ErrorResponseType[Literal["invalid_token_type"]],
        401: ErrorResponseType[
            Literal[
                "expired_token",
                "invalid_token",
                "invalid_user",
                "session_not_found",
                "session_expired",
                "token_reuse_detected",
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

    # A signature alone is not authority to mint tokens: the session behind the
    # token has to still be live, or logging out would not end the refresh path.
    try:
        session = Session.objects.get(id=refresh_payload.session_id)
    except Session.DoesNotExist:
        raise APIError("session_not_found", http_status_code=401)

    if session.expired_at and session.expired_at < timezone.now():
        raise APIError("session_expired", http_status_code=401)

    if session.user_id != refresh_payload.user_id:
        raise APIError("invalid_token", http_status_code=401)

    # A refresh token this session has already rotated past is either a replay
    # of a stolen token or a token that outlived its rotation. Either way the
    # session is no longer trustworthy, so end it rather than serve it.
    if not session.accepts_refresh_jti(refresh_payload.jti):
        session.invalidate_session()
        raise APIError("token_reuse_detected", http_status_code=401)

    try:
        user = User.objects.get(id=refresh_payload.user_id, is_active=True)
    except User.DoesNotExist:
        raise APIError("invalid_user", http_status_code=401)

    access_token, new_refresh = _issue_token_pair(user, session)

    return _build_login_response(access_token=access_token, refresh_token=new_refresh)


@router.get(
    "sessions/",
    summary="List active sessions",
    response={200: list[SessionResponse]},
    auth=JWTAuth(),
)
def list_active_sessions(request: AuthedRequest):
    return request.auth.user.jwt_sessions.active()


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
    Session.invalidate_all_user_sessions(request.auth.user)

    response = HttpResponse(status=200)
    if jwt_settings_module.jwt_settings.REFRESH_TOKEN_TRANSPORT in {"cookie", "both"}:
        _delete_refresh_cookie(response)
    return response
