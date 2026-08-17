import hashlib
import time
from functools import wraps
from math import ceil
from secrets import token_urlsafe
from typing import Any, Literal

from django.contrib.auth import get_user_model
from django.core.cache import caches
from django.core.exceptions import ValidationError
from django.db import DataError, OperationalError, connection, transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.middleware.csrf import CsrfViewMiddleware, get_token
from django.utils import timezone
from django.utils.module_loading import import_string
from ninja import Router
from ninja.utils import check_csrf

from . import settings as jwt_settings_module
from .auth_classes import AuthedRequest, JWTAuth
from .cryptography import decode_jwt, generate_jwt
from .errors import APIError, JWTExpiredError, JWTInvalidPayloadFormat, JWTInvalidTokenError
from .geolocation import resolve_location
from .handlers import apply_no_store
from .models import SecurityStampChangedError, Session, security_stamp_for_user
from .request import get_client_ip, get_user_agent
from .types import ErrorResponseType, LoginSchema, RefreshTokenSchema, SessionResponse, TokenSchema

User = get_user_model()
router = Router(tags=["Authentication"])
_SESSION_ID_MAX_LENGTH = 43


def _no_store_view(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        return apply_no_store(view(request, *args, **kwargs))

    return wrapped


def _is_json_media_type(value: str | None) -> bool:
    if not value:
        return False
    media_type = value.split(";", 1)[0].strip().lower()
    return media_type == "application/json" or (media_type.startswith("application/") and media_type.endswith("+json"))


def _enforce_rate_limit(request: HttpRequest, scope: str, rate: tuple[int, int] | None) -> None:
    if rate is None:
        return
    count, duration = rate
    identity = get_client_ip(request) or "unknown"
    digest = hashlib.sha256(identity.encode()).hexdigest()
    bucket = int(time.time()) // duration
    key = f"jwt_ninja:throttle:{scope}:{digest}:{bucket}"
    try:
        throttle_cache = caches[jwt_settings_module.jwt_settings.THROTTLE_CACHE_ALIAS]
        if throttle_cache.add(key, 1, timeout=duration + 1):
            current = 1
        else:
            current = throttle_cache.incr(key)
    except Exception:
        # Authentication must not become unthrottled during a cache outage.
        raise APIError("rate_limited", 429, retry_after=duration) from None
    if current > count:
        retry_after = max(1, duration - (int(time.time()) % duration))
        raise APIError("rate_limited", 429, retry_after=ceil(retry_after))


class _BrowserBoundaryGuard:
    """Ninja auth callback: runs before request body parsing."""

    def __init__(self, scope: Literal["login", "refresh"]):
        self.scope = scope

    def __call__(self, request: HttpRequest) -> bool:
        if not _is_json_media_type(request.headers.get("Content-Type")):
            raise APIError("unsupported_media_type", 415)
        config = jwt_settings_module.jwt_settings
        if config.REFRESH_TOKEN_TRANSPORT in {"cookie", "both"} and check_csrf(request):
            raise APIError("csrf_failed", 403)
        rate = config.login_rate if self.scope == "login" else config.refresh_rate
        _enforce_rate_limit(request, self.scope, rate)
        # Materialize the body only after browser and pre-auth rate controls.
        if not request.body:
            raise APIError("unsupported_media_type", 415)
        return True


def _set_refresh_cookie(response: HttpResponse, refresh_token: str) -> None:
    config = jwt_settings_module.jwt_settings
    response.set_cookie(
        key=config.REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=config.REFRESH_TOKEN_EXPIRE_SECONDS,
        path=config.REFRESH_COOKIE_PATH,
        domain=config.REFRESH_COOKIE_DOMAIN,
        secure=config.REFRESH_COOKIE_SECURE,
        httponly=config.REFRESH_COOKIE_HTTPONLY,
        samesite=config.REFRESH_COOKIE_SAMESITE,
    )


def _delete_refresh_cookie(response: HttpResponse) -> None:
    config = jwt_settings_module.jwt_settings
    response.delete_cookie(
        key=config.REFRESH_COOKIE_NAME,
        path=config.REFRESH_COOKIE_PATH,
        domain=config.REFRESH_COOKIE_DOMAIN,
        samesite=config.REFRESH_COOKIE_SAMESITE,
    )


def _build_login_response(access_token: str, refresh_token: str) -> JsonResponse:
    config = jwt_settings_module.jwt_settings
    payload = {"access_token": access_token}
    if config.REFRESH_TOKEN_TRANSPORT in {"body", "both"}:
        payload["refresh_token"] = refresh_token
    response = JsonResponse(payload)
    if config.REFRESH_TOKEN_TRANSPORT in {"cookie", "both"}:
        _set_refresh_cookie(response, refresh_token)
    return response


def _mint_token_pair(user, session: Session, refresh_jti: str) -> tuple[str, str]:
    now = int(time.time())
    config = jwt_settings_module.jwt_settings
    access_payload = config.payload_class(
        user_id=user.id,
        type="access",
        exp=now + config.ACCESS_TOKEN_EXPIRE_SECONDS,
        session_id=session.id,
    )
    refresh_payload = config.payload_class(
        user_id=user.id,
        type="refresh",
        exp=now + config.REFRESH_TOKEN_EXPIRE_SECONDS,
        session_id=session.id,
        jti=refresh_jti,
    )
    return generate_jwt(access_payload), generate_jwt(refresh_payload)


def _get_refresh_token(request: HttpRequest, payload: RefreshTokenSchema | None) -> str:
    config = jwt_settings_module.jwt_settings
    body_token = payload.refresh_token if payload else None
    if config.REFRESH_TOKEN_TRANSPORT == "body":
        token = body_token
    elif config.REFRESH_TOKEN_TRANSPORT == "cookie":
        token = request.COOKIES.get(config.REFRESH_COOKIE_NAME)
    else:
        token = body_token or request.COOKIES.get(config.REFRESH_COOKIE_NAME)
    if not token or len(token) > config.MAX_TOKEN_LENGTH:
        raise APIError("invalid_token", 401)
    return token


@router.get(
    "csrf/",
    summary="Bootstrap browser CSRF protection",
    description="Set Django's CSRF cookie and return the masked token for the X-CSRFToken header.",
    response={200: dict[str, str]},
    auth=None,
)
def csrf_bootstrap(request: HttpRequest) -> HttpResponse:
    token = get_token(request)
    response = JsonResponse({"csrf_token": token})
    return CsrfViewMiddleware(lambda req: response).process_response(request, response)


_CSRF_OPENAPI_PARAMETER = {
    "parameters": [
        {
            "in": "header",
            "name": "X-CSRFToken",
            "required": False,
            "schema": {"type": "string"},
            "description": (
                "Required for login/refresh when refresh transport is cookie or both; obtain it from GET csrf/."
            ),
        }
    ]
}


@router.post(
    "login/",
    summary="Obtain a new access token",
    description="Accepts JSON only. Cookie/both refresh transport additionally requires Django CSRF.",
    openapi_extra=_CSRF_OPENAPI_PARAMETER,
    response={
        200: TokenSchema,
        422: dict[str, Any],
        401: ErrorResponseType[Literal["invalid_credentials"]],
        403: ErrorResponseType[Literal["csrf_failed"]],
        415: ErrorResponseType[Literal["unsupported_media_type"]],
        429: ErrorResponseType[Literal["rate_limited"]],
    },
    auth=_BrowserBoundaryGuard("login"),
)
def login(request: HttpRequest, payload: LoginSchema) -> HttpResponse:
    config = jwt_settings_module.jwt_settings
    if len(payload.username) > config.MAX_USERNAME_LENGTH or len(payload.password) > config.MAX_PASSWORD_LENGTH:
        raise APIError("invalid_credentials", 401)
    user = import_string(config.USER_LOGIN_AUTHENTICATOR)(request, payload)
    if not user:
        raise APIError("invalid_credentials", 401)

    # Snapshot the exact credentials that authentication accepted. The locked
    # row is compared to this value before cap eviction or session insertion.
    try:
        authenticated_stamp = security_stamp_for_user(user)
    except Exception:
        raise APIError("invalid_credentials", 401) from None
    client_ip = get_client_ip(request)
    location = resolve_location(client_ip)

    attempts = 5 if connection.vendor == "sqlite" else 1
    for attempt in range(attempts):
        try:
            with transaction.atomic():  # pyrefly: ignore [bad-context-manager]
                session = Session.create_session(
                    user=user,
                    ip_address=client_ip if config.PERSIST_CLIENT_IP else None,
                    user_agent=get_user_agent(request),
                    location=location.model_dump() if location else None,
                    expected_security_stamp=authenticated_stamp,
                )
                jti = session.initialize_refresh_jti()
                access_token, refresh_token = _mint_token_pair(user, session, jti)
            return _build_login_response(access_token, refresh_token)
        except SecurityStampChangedError:
            raise APIError("invalid_credentials", 401) from None
        except OperationalError as exc:
            is_sqlite_lock = connection.vendor == "sqlite" and "locked" in str(exc).lower()
            if not is_sqlite_lock or attempt == attempts - 1:
                raise
            time.sleep(0.01 * (2**attempt))

    raise RuntimeError("unreachable")


@router.post(
    "refresh/",
    summary="Refresh an access token",
    description=(
        "Accepts JSON only and strictly consumes a single-use refresh token. "
        "Cookie/both transport requires Django CSRF. Retry ambiguity requires reauthentication."
    ),
    openapi_extra=_CSRF_OPENAPI_PARAMETER,
    response={
        200: TokenSchema,
        422: dict[str, Any],
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
        403: ErrorResponseType[Literal["csrf_failed"]],
        415: ErrorResponseType[Literal["unsupported_media_type"]],
        429: ErrorResponseType[Literal["rate_limited"]],
    },
    auth=_BrowserBoundaryGuard("refresh"),
)
def new_refresh_token(request: HttpRequest, payload: RefreshTokenSchema | None = None) -> Any:
    token = _get_refresh_token(request, payload)
    try:
        refresh_payload = decode_jwt(token, jwt_settings_module.jwt_settings.payload_class)
    except JWTExpiredError:
        raise APIError("expired_token", 401)
    except (JWTInvalidTokenError, JWTInvalidPayloadFormat):
        raise APIError("invalid_token", 401)
    if refresh_payload.type != "refresh":
        raise APIError("invalid_token_type", 400)
    if (
        not refresh_payload.session_id
        or len(refresh_payload.session_id) > _SESSION_ID_MAX_LENGTH
        or not refresh_payload.jti
        or len(refresh_payload.jti) > 43
    ):
        raise APIError("invalid_token", 401)

    try:
        session = Session.objects.get(id=refresh_payload.session_id)
    except Session.DoesNotExist:
        raise APIError("session_not_found", 401)
    except (ValidationError, DataError, TypeError, ValueError):
        raise APIError("invalid_token", 401)
    if session.user_id != refresh_payload.user_id:
        raise APIError("invalid_token", 401)
    if session.expired_at is not None and session.expired_at <= timezone.now():
        raise APIError("session_expired", 401)

    try:
        user = User.objects.get(id=refresh_payload.user_id, is_active=True)
    except User.DoesNotExist:
        raise APIError("invalid_user", 401)
    except (ValidationError, DataError, TypeError, ValueError):
        raise APIError("invalid_token", 401)
    if not session.security_stamp_matches(user):
        raise APIError("session_expired", 401)
    expected_stamp = session.security_stamp
    if expected_stamp is None:
        # security_stamp_matches already expires this case; keep this explicit
        # for optimized Python and static type narrowing.
        raise APIError("session_expired", 401)

    # Mint against a candidate JTI before any durable state is consumed. If
    # CAS loses, these tokens are discarded and never returned.
    candidate_jti = token_urlsafe(32)
    access_token, refresh_token = _mint_token_pair(user, session, candidate_jti)
    status, new_jti = Session.consume_refresh_jti(
        session_id=session.id,
        user_id=user.id,
        presented_jti=refresh_payload.jti,
        replacement_jti=candidate_jti,
        expected_security_stamp=expected_stamp,
    )
    if status == "missing":
        raise APIError("session_not_found", 401)
    if status == "wrong_user":
        raise APIError("invalid_token", 401)
    if status in {"expired", "security_changed"}:
        raise APIError("session_expired", 401)
    if status == "reused":
        raise APIError("token_reuse_detected", 401)
    if status != "consumed" or new_jti is None:
        raise APIError("invalid_token", 401)

    return _build_login_response(access_token, refresh_token)


@router.get("sessions/", summary="List active sessions", response={200: list[SessionResponse]}, auth=JWTAuth())
def list_active_sessions(request: AuthedRequest):
    # MAX_ACTIVE_SESSIONS already bounds this response, so every active
    # session is returned without a second, silently truncating limit.
    return request.auth.user.jwt_sessions.active().order_by("-updated_at", "-id")


@router.delete(
    "sessions/{session_id}/",
    summary="Revoke a session",
    response={200: None, 404: ErrorResponseType[Literal["session_not_found"]]},
    auth=JWTAuth(),
)
def revoke_session(request: AuthedRequest, session_id: str) -> HttpResponse:
    if len(session_id) > _SESSION_ID_MAX_LENGTH:
        raise APIError("session_not_found", 404)
    try:
        session = request.auth.user.jwt_sessions.active().get(id=session_id)
    except (Session.DoesNotExist, ValidationError, DataError, ValueError):
        raise APIError("session_not_found", 404)
    session.invalidate_session()
    response = HttpResponse(status=200)
    if session.id == request.auth.session.id and jwt_settings_module.jwt_settings.REFRESH_TOKEN_TRANSPORT in {
        "cookie",
        "both",
    }:
        _delete_refresh_cookie(response)
    return response


@router.post("logout/", summary="Logout", response={200: None}, auth=JWTAuth())
def logout(request: AuthedRequest) -> HttpResponse:
    # Revoke durable state before constructing/clearing the client cookie.
    request.auth.session.invalidate_session()
    response = HttpResponse(status=200)
    if jwt_settings_module.jwt_settings.REFRESH_TOKEN_TRANSPORT in {"cookie", "both"}:
        _delete_refresh_cookie(response)
    return response


@router.post("logout/all/", summary="Logout from all sessions", response={200: None}, auth=JWTAuth())
def logout_all(request: AuthedRequest) -> HttpResponse:
    Session.invalidate_all_user_sessions(request.auth.user)
    response = HttpResponse(status=200)
    if jwt_settings_module.jwt_settings.REFRESH_TOKEN_TRANSPORT in {"cookie", "both"}:
        _delete_refresh_cookie(response)
    return response


router.add_decorator(_no_store_view, mode="view")
