import ipaddress
from collections.abc import Callable
from typing import Literal

import jwt
import jwt.algorithms
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.utils.module_loading import import_string
from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from .types import GeoLocation, JWTPayload

_HMAC_MIN_KEY_BYTES = {"HS256": 32, "HS384": 48, "HS512": 64}
_SUPPORTED_ALGORITHMS = set(_HMAC_MIN_KEY_BYTES) | {
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
}


def _django_setting(name: str, default=None):
    return getattr(settings, f"JWT_{name}", default)


def _parse_rate(value: str | None, name: str) -> tuple[int, int] | None:
    if value is None or value == "0":
        return None
    periods = {"s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "hour": 3600}
    try:
        count_text, period_text = value.split("/", 1)
        count = int(count_text)
        multiplier = 1
        for suffix, seconds in periods.items():
            if period_text.endswith(suffix):
                prefix = period_text[: -len(suffix)]
                multiplier = int(prefix) if prefix else 1
                duration = multiplier * seconds
                break
        else:
            raise ValueError
        if count <= 0 or duration <= 0:
            raise ValueError
    except (AttributeError, TypeError, ValueError):
        raise ImproperlyConfigured(f"JWT_{name} must be a rate such as '5/min', or null/'0' to disable.") from None
    return count, duration


def _validate_key_profile(config: "JWTSettings") -> None:
    algorithm = config.ALGORITHM
    if algorithm.lower() == "none":
        raise ImproperlyConfigured("JWT_ALGORITHM cannot be 'none'.")
    if algorithm not in _SUPPORTED_ALGORITHMS or algorithm not in jwt.algorithms.get_default_algorithms():
        raise ImproperlyConfigured(f"JWT_ALGORITHM {algorithm!r} is unsupported or unavailable.")

    signing_key = config.SECRET_KEY
    if not signing_key or not signing_key.strip():
        raise ImproperlyConfigured("JWT_SECRET_KEY must be an explicit, non-empty dedicated JWT signing key.")

    if algorithm in _HMAC_MIN_KEY_BYTES:
        minimum = _HMAC_MIN_KEY_BYTES[algorithm]
        encoded_key = signing_key.encode()
        if len(encoded_key) < minimum:
            raise ImproperlyConfigured(f"JWT_SECRET_KEY must be at least {minimum} bytes for {algorithm}.")
        normalized = signing_key.lstrip()
        if "-----BEGIN " in normalized or normalized.startswith(("ssh-", '{"kty"', "{'kty'")):
            raise ImproperlyConfigured("HMAC JWT_SECRET_KEY must be raw secret material, not an asymmetric key.")
        if config.VERIFYING_KEY is not None and config.VERIFYING_KEY != signing_key:
            raise ImproperlyConfigured("HMAC JWT_VERIFYING_KEY must be omitted or exactly match JWT_SECRET_KEY.")
        try:
            probe = jwt.encode({"probe": True}, signing_key, algorithm=algorithm)
            jwt.decode(probe, signing_key, algorithms=[algorithm], options={"verify_exp": False})
        except Exception as exc:
            raise ImproperlyConfigured("HMAC JWT_SECRET_KEY is malformed or incompatible.") from exc
        return

    if not config.VERIFYING_KEY or not config.VERIFYING_KEY.strip():
        raise ImproperlyConfigured("Asymmetric JWT algorithms require an explicit JWT_VERIFYING_KEY.")

    try:
        algorithm_impl = jwt.algorithms.get_default_algorithms()[algorithm]
        signing = algorithm_impl.prepare_key(signing_key)
        verifying = algorithm_impl.prepare_key(config.VERIFYING_KEY)
        if algorithm.startswith(("RS", "PS")):
            if getattr(signing, "key_size", 0) < 2048 or getattr(verifying, "key_size", 0) < 2048:
                raise ImproperlyConfigured("RSA/PS JWT keys must be at least 2048 bits.")
        probe = jwt.encode({"probe": True}, signing_key, algorithm=algorithm)
        jwt.decode(probe, config.VERIFYING_KEY, algorithms=[algorithm], options={"verify_exp": False})
    except ImproperlyConfigured:
        raise
    except Exception as exc:
        raise ImproperlyConfigured(
            "JWT_SECRET_KEY/JWT_VERIFYING_KEY are malformed, incompatible, public-only, or do not match."
        ) from exc


class JWTSettings(BaseSettings):
    # SECRET_KEY retains the public attribute used by earlier releases, but no
    # longer falls back to Django's application-wide SECRET_KEY.
    SECRET_KEY: str = Field(default_factory=lambda: _django_setting("SECRET_KEY", ""))
    VERIFYING_KEY: str | None = Field(default_factory=lambda: _django_setting("VERIFYING_KEY"))
    ALGORITHM: str = Field(default_factory=lambda: _django_setting("ALGORITHM", "HS256"))
    ISSUER: str = Field(default_factory=lambda: _django_setting("ISSUER", ""))
    AUDIENCE: str = Field(default_factory=lambda: _django_setting("AUDIENCE", ""))
    LEEWAY_SECONDS: int = Field(default_factory=lambda: _django_setting("LEEWAY_SECONDS", 0), ge=0, le=300)

    ACCESS_TOKEN_EXPIRE_SECONDS: int = Field(
        default_factory=lambda: _django_setting("ACCESS_TOKEN_EXPIRE_SECONDS", 300), ge=1, le=86400
    )
    REFRESH_TOKEN_EXPIRE_SECONDS: int = Field(
        default_factory=lambda: _django_setting("REFRESH_TOKEN_EXPIRE_SECONDS", 14 * 86400), ge=1, le=31536000
    )
    SESSION_EXPIRE_SECONDS: int = Field(
        default_factory=lambda: _django_setting("SESSION_EXPIRE_SECONDS", 14 * 86400), ge=0, le=31536000
    )
    MAX_TOKEN_LENGTH: int = Field(default_factory=lambda: _django_setting("MAX_TOKEN_LENGTH", 8192), ge=256, le=65536)
    MAX_USERNAME_LENGTH: int = Field(default_factory=lambda: _django_setting("MAX_USERNAME_LENGTH", 254), ge=1, le=1024)
    MAX_PASSWORD_LENGTH: int = Field(
        default_factory=lambda: _django_setting("MAX_PASSWORD_LENGTH", 1024), ge=1, le=65536
    )
    MAX_ACTIVE_SESSIONS: int = Field(default_factory=lambda: _django_setting("MAX_ACTIVE_SESSIONS", 20), ge=1, le=1000)

    USER_LOGIN_AUTHENTICATOR: str = Field(
        default_factory=lambda: _django_setting(
            "USER_LOGIN_AUTHENTICATOR", "jwt_ninja.authenticators.django_user_authenticator"
        )
    )
    JWT_PAYLOAD_CLASS: str = Field(
        default_factory=lambda: _django_setting("PAYLOAD_CLASS", "jwt_ninja.types.JWTPayload")
    )
    REFRESH_TOKEN_TRANSPORT: Literal["body", "cookie", "both"] = Field(
        default_factory=lambda: _django_setting("REFRESH_TOKEN_TRANSPORT", "body")
    )
    REFRESH_COOKIE_NAME: str = Field(default_factory=lambda: _django_setting("REFRESH_COOKIE_NAME", "refresh_token"))
    REFRESH_COOKIE_SECURE: bool = Field(default_factory=lambda: _django_setting("REFRESH_COOKIE_SECURE", True))
    REFRESH_COOKIE_HTTPONLY: bool = Field(default_factory=lambda: _django_setting("REFRESH_COOKIE_HTTPONLY", True))
    REFRESH_COOKIE_SAMESITE: Literal["Lax", "Strict", "None"] = Field(
        default_factory=lambda: _django_setting("REFRESH_COOKIE_SAMESITE", "Lax")
    )
    REFRESH_COOKIE_PATH: str = Field(default_factory=lambda: _django_setting("REFRESH_COOKIE_PATH", "/auth/refresh/"))
    REFRESH_COOKIE_DOMAIN: str | None = Field(default_factory=lambda: _django_setting("REFRESH_COOKIE_DOMAIN"))
    REFRESH_TOKEN_REUSE_GRACE_SECONDS: int = Field(
        default_factory=lambda: _django_setting("REFRESH_TOKEN_REUSE_GRACE_SECONDS", 0), ge=0
    )

    LOGIN_THROTTLE_RATE: str | None = Field(default_factory=lambda: _django_setting("LOGIN_THROTTLE_RATE", "5/min"))
    REFRESH_THROTTLE_RATE: str | None = Field(
        default_factory=lambda: _django_setting("REFRESH_THROTTLE_RATE", "30/min")
    )
    THROTTLE_CACHE_ALIAS: str = Field(default_factory=lambda: _django_setting("THROTTLE_CACHE_ALIAS", "default"))
    TRUSTED_PROXY_CIDRS: list[str] = Field(default_factory=lambda: _django_setting("TRUSTED_PROXY_CIDRS", []))
    MAX_FORWARDED_HEADER_LENGTH: int = Field(
        default_factory=lambda: _django_setting("MAX_FORWARDED_HEADER_LENGTH", 2048), ge=64, le=65536
    )
    MAX_FORWARDED_HOPS: int = Field(default_factory=lambda: _django_setting("MAX_FORWARDED_HOPS", 10), ge=1, le=100)

    GEOLOCATION_PROVIDER: str | None = Field(default_factory=lambda: _django_setting("GEOLOCATION_PROVIDER"))
    GEOLOCATION_THIRD_PARTY_CONSENT: bool = Field(
        default_factory=lambda: _django_setting("GEOLOCATION_THIRD_PARTY_CONSENT", False)
    )
    GEOLOCATION_TIMEOUT_SECONDS: float = Field(
        default_factory=lambda: _django_setting("GEOLOCATION_TIMEOUT_SECONDS", 2.0), gt=0, le=30
    )
    GEOLOCATION_MAX_RESPONSE_BYTES: int = Field(
        default_factory=lambda: _django_setting("GEOLOCATION_MAX_RESPONSE_BYTES", 32768), ge=256, le=1048576
    )
    PERSIST_CLIENT_IP: bool = Field(default_factory=lambda: _django_setting("PERSIST_CLIENT_IP", True))

    model_config = SettingsConfigDict(env_prefix="JWT_", case_sensitive=True)

    _JWT_PAYLOAD_CLASS: type[JWTPayload]
    _GEOLOCATION_PROVIDER: Callable[[str], GeoLocation | None] | None
    _TRUSTED_PROXY_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    _LOGIN_RATE: tuple[int, int] | None
    _REFRESH_RATE: tuple[int, int] | None

    def __init__(self):
        django_overrides = {}
        for field_name in type(self).model_fields:
            django_key = field_name if field_name.startswith("JWT_") else f"JWT_{field_name}"
            if hasattr(settings, django_key):
                django_overrides[field_name] = getattr(settings, django_key)
        try:
            super().__init__(**django_overrides)
        except ValidationError as exc:
            raise ImproperlyConfigured(f"Invalid JWT setting: {exc}") from exc

        if not self.ISSUER.strip() or not self.AUDIENCE.strip():
            raise ImproperlyConfigured("JWT_ISSUER and JWT_AUDIENCE must be explicit non-empty strings.")
        if not self.THROTTLE_CACHE_ALIAS.strip():
            raise ImproperlyConfigured("JWT_THROTTLE_CACHE_ALIAS must be a non-empty Django cache alias.")
        if self.REFRESH_TOKEN_REUSE_GRACE_SECONDS != 0:
            raise ImproperlyConfigured(
                "JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS must be 0; refresh tokens are single-use."
            )
        if self.REFRESH_COOKIE_SAMESITE == "None" and not (self.REFRESH_COOKIE_SECURE and self.REFRESH_COOKIE_HTTPONLY):
            raise ImproperlyConfigured("SameSite=None refresh cookies require Secure=True and HttpOnly=True.")
        if self.SESSION_EXPIRE_SECONDS and self.SESSION_EXPIRE_SECONDS > self.REFRESH_TOKEN_EXPIRE_SECONDS:
            raise ImproperlyConfigured("JWT_SESSION_EXPIRE_SECONDS cannot exceed the refresh token lifetime.")

        try:
            payload_class = import_string(self.JWT_PAYLOAD_CLASS)
            if not isinstance(payload_class, type) or not issubclass(payload_class, JWTPayload):
                raise ImproperlyConfigured("JWT_PAYLOAD_CLASS must resolve to a JWTPayload subclass.")
            self._JWT_PAYLOAD_CLASS = payload_class
            self._GEOLOCATION_PROVIDER = import_string(self.GEOLOCATION_PROVIDER) if self.GEOLOCATION_PROVIDER else None
            self._TRUSTED_PROXY_NETWORKS = tuple(
                ipaddress.ip_network(value, strict=False) for value in self.TRUSTED_PROXY_CIDRS
            )
        except ImproperlyConfigured:
            raise
        except (ImportError, AttributeError, TypeError, ValueError) as exc:
            raise ImproperlyConfigured("JWT payload/provider path or trusted proxy CIDR is invalid.") from exc
        if self.GEOLOCATION_PROVIDER == "jwt_ninja.geolocation.ipapi_co_geolocator" and not (
            self.GEOLOCATION_THIRD_PARTY_CONSENT
        ):
            raise ImproperlyConfigured("The ipapi.co provider requires JWT_GEOLOCATION_THIRD_PARTY_CONSENT=True.")

        self._LOGIN_RATE = _parse_rate(self.LOGIN_THROTTLE_RATE, "LOGIN_THROTTLE_RATE")
        self._REFRESH_RATE = _parse_rate(self.REFRESH_THROTTLE_RATE, "REFRESH_THROTTLE_RATE")
        if (self._LOGIN_RATE or self._REFRESH_RATE) and self.THROTTLE_CACHE_ALIAS not in (settings.CACHES or {}):
            # A missing alias would otherwise surface only as every login and
            # refresh failing closed with 429 at request time.
            raise ImproperlyConfigured(
                f"JWT_THROTTLE_CACHE_ALIAS {self.THROTTLE_CACHE_ALIAS!r} is not a configured Django cache."
            )
        _validate_key_profile(self)

    @property
    def payload_class(self) -> type[JWTPayload]:
        return self._JWT_PAYLOAD_CLASS

    @property
    def geolocation_provider(self) -> Callable[[str], GeoLocation | None] | None:
        return self._GEOLOCATION_PROVIDER

    @property
    def trusted_proxy_networks(self):
        return self._TRUSTED_PROXY_NETWORKS

    @property
    def login_rate(self) -> tuple[int, int] | None:
        return self._LOGIN_RATE

    @property
    def refresh_rate(self) -> tuple[int, int] | None:
        return self._REFRESH_RATE

    @property
    def verification_key(self) -> str:
        return self.VERIFYING_KEY or self.SECRET_KEY


jwt_settings = JWTSettings()


def reload_jwt_settings(*args, **kwargs):
    setting = kwargs["setting"]
    if not setting.startswith("JWT_"):
        return
    fresh = JWTSettings()
    for field_name in type(jwt_settings).model_fields:
        setattr(jwt_settings, field_name, getattr(fresh, field_name))
    jwt_settings._JWT_PAYLOAD_CLASS = fresh._JWT_PAYLOAD_CLASS
    jwt_settings._GEOLOCATION_PROVIDER = fresh._GEOLOCATION_PROVIDER
    jwt_settings._TRUSTED_PROXY_NETWORKS = fresh._TRUSTED_PROXY_NETWORKS
    jwt_settings._LOGIN_RATE = fresh._LOGIN_RATE
    jwt_settings._REFRESH_RATE = fresh._REFRESH_RATE


setting_changed.connect(reload_jwt_settings)
