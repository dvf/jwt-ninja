import warnings
from collections.abc import Callable
from typing import Literal

import jwt.algorithms
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.utils.module_loading import import_string
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .types import GeoLocation, JWTPayload


class InsecureJWTKeyWarning(UserWarning):
    """
    Emitted when the configured JWT signing key is shorter than the HMAC
    algorithm's recommended minimum per RFC 7518 §3.2. Short keys weaken
    HMAC security; PyJWT also emits its own InsecureKeyLengthWarning at
    encode/decode time.
    """


# RFC 7518 §3.2: HMAC keys should be at least the hash output size.
_HMAC_MIN_KEY_BYTES = {
    "HS256": 32,
    "HS384": 48,
    "HS512": 64,
}


def _validate_algorithm(algorithm: str) -> None:
    """
    Reject algorithms PyJWT cannot use, and the unsigned `none` algorithm.

    The set of usable algorithms depends on whether PyJWT's optional
    cryptography extra is installed, so it is read from PyJWT rather than
    hardcoded — `pip install pyjwt[crypto]` is what unlocks RS*/ES*/PS*/EdDSA.
    """
    supported = set(jwt.algorithms.get_default_algorithms()) - {"none"}
    if algorithm in supported:
        return

    if algorithm.lower() == "none":
        raise ImproperlyConfigured("JWT_ALGORITHM cannot be 'none'. Unsigned tokens can be forged by anyone.")
    raise ImproperlyConfigured(
        f"JWT_ALGORITHM {algorithm!r} is not available. Supported algorithms are "
        f"{', '.join(sorted(supported))}. Asymmetric algorithms require PyJWT's "
        f"cryptography extra: pip install 'pyjwt[crypto]'."
    )


def _warn_if_key_too_short(secret_key: str, algorithm: str) -> None:
    minimum = _HMAC_MIN_KEY_BYTES.get(algorithm)
    if minimum is None:
        return
    key_bytes = len(secret_key.encode("utf-8"))
    if key_bytes >= minimum:
        return
    warnings.warn(
        f"JWT signing key is {key_bytes} bytes, but {algorithm} requires at least "
        f"{minimum} bytes per RFC 7518 §3.2. Set JWT_SECRET_KEY (or rotate Django's "
        f"SECRET_KEY) to a random value with at least {minimum} bytes of entropy. "
        f"Short HMAC keys reduce the security margin of your tokens — an attacker "
        f"who recovers the key can forge arbitrary tokens.",
        InsecureJWTKeyWarning,
        stacklevel=3,
    )


class JWTSettings(BaseSettings):
    SECRET_KEY: str = Field(default_factory=lambda: settings.SECRET_KEY)
    ALGORITHM: str = Field(default_factory=lambda: getattr(settings, "JWT_ALGORITHM", "HS256"))
    ACCESS_TOKEN_EXPIRE_SECONDS: int = Field(
        default_factory=lambda: getattr(settings, "JWT_ACCESS_TOKEN_EXPIRE_SECONDS", 300)
    )
    REFRESH_TOKEN_EXPIRE_SECONDS: int = Field(
        default_factory=lambda: getattr(settings, "JWT_REFRESH_TOKEN_EXPIRE_SECONDS", 365 * 3600)
    )
    SESSION_EXPIRE_SECONDS: int = Field(
        default_factory=lambda: getattr(settings, "JWT_SESSION_EXPIRE_SECONDS", 365 * 3600)
    )
    USER_LOGIN_AUTHENTICATOR: str = Field(
        default_factory=lambda: getattr(
            settings,
            "JWT_USER_LOGIN_AUTHENTICATOR",
            "jwt_ninja.authenticators.django_user_authenticator",
        )
    )
    JWT_PAYLOAD_CLASS: str = Field(
        default_factory=lambda: getattr(settings, "JWT_PAYLOAD_CLASS", "jwt_ninja.types.JWTPayload")
    )
    REFRESH_TOKEN_TRANSPORT: Literal["body", "cookie", "both"] = Field(
        default_factory=lambda: getattr(settings, "JWT_REFRESH_TOKEN_TRANSPORT", "body")
    )
    REFRESH_COOKIE_NAME: str = Field(
        default_factory=lambda: getattr(settings, "JWT_REFRESH_COOKIE_NAME", "refresh_token")
    )
    REFRESH_COOKIE_SECURE: bool = Field(default_factory=lambda: getattr(settings, "JWT_REFRESH_COOKIE_SECURE", True))
    REFRESH_COOKIE_HTTPONLY: bool = Field(
        default_factory=lambda: getattr(settings, "JWT_REFRESH_COOKIE_HTTPONLY", True)
    )
    REFRESH_COOKIE_SAMESITE: Literal["Lax", "Strict", "None"] = Field(
        default_factory=lambda: getattr(settings, "JWT_REFRESH_COOKIE_SAMESITE", "Lax")
    )
    REFRESH_COOKIE_PATH: str = Field(
        default_factory=lambda: getattr(settings, "JWT_REFRESH_COOKIE_PATH", "/auth/refresh/")
    )
    REFRESH_COOKIE_DOMAIN: str | None = Field(
        default_factory=lambda: getattr(settings, "JWT_REFRESH_COOKIE_DOMAIN", None)
    )
    REFRESH_TOKEN_REUSE_GRACE_SECONDS: int = Field(
        default_factory=lambda: getattr(settings, "JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS", 30)
    )
    GEOLOCATION_PROVIDER: str | None = Field(
        default_factory=lambda: getattr(settings, "JWT_GEOLOCATION_PROVIDER", None)
    )

    model_config = SettingsConfigDict(
        env_prefix="JWT_",
        case_sensitive=True,
    )

    _JWT_PAYLOAD_CLASS: type[JWTPayload]
    _GEOLOCATION_PROVIDER: Callable[[str], GeoLocation | None] | None

    def __init__(self):
        # Pull values from Django settings so that JWT_* settings in settings.py
        # (and test-time overrides via override_settings) take precedence over
        # the pydantic defaults. Env vars still work via pydantic-settings.
        django_overrides = {}
        for field_name in type(self).model_fields:
            django_key = field_name if field_name.startswith("JWT_") else f"JWT_{field_name}"
            if hasattr(settings, django_key):
                django_overrides[field_name] = getattr(settings, django_key)
        super().__init__(**django_overrides)
        self._JWT_PAYLOAD_CLASS = import_string(self.JWT_PAYLOAD_CLASS)
        self._GEOLOCATION_PROVIDER = import_string(self.GEOLOCATION_PROVIDER) if self.GEOLOCATION_PROVIDER else None
        _validate_algorithm(self.ALGORITHM)
        _warn_if_key_too_short(self.SECRET_KEY, self.ALGORITHM)

    @property
    def payload_class(self) -> type[JWTPayload]:
        return self._JWT_PAYLOAD_CLASS

    @property
    def geolocation_provider(self) -> Callable[[str], GeoLocation | None] | None:
        return self._GEOLOCATION_PROVIDER


jwt_settings = JWTSettings()


def reload_jwt_settings(*args, **kwargs):
    # Mutate the existing jwt_settings instance in place rather than rebinding
    # the module-level name. Other modules hold references via
    # `from .settings import jwt_settings`; reassignment would leave those
    # bindings stale.
    setting = kwargs["setting"]
    if not setting.startswith("JWT_"):
        return
    fresh = JWTSettings()
    for field_name in type(jwt_settings).model_fields:
        setattr(jwt_settings, field_name, getattr(fresh, field_name))
    jwt_settings._JWT_PAYLOAD_CLASS = fresh._JWT_PAYLOAD_CLASS
    jwt_settings._GEOLOCATION_PROVIDER = fresh._GEOLOCATION_PROVIDER


setting_changed.connect(reload_jwt_settings)
