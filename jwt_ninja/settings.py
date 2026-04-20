from django.conf import settings
from django.core.signals import setting_changed
from django.utils.module_loading import import_string
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .types import JWTPayload


class JWTSettings(BaseSettings):
    SECRET_KEY: str = Field(default_factory=lambda: settings.SECRET_KEY)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_SECONDS: int = 300  # 5 minutes
    REFRESH_TOKEN_EXPIRE_SECONDS: int = 365 * 3600  # 1 year
    SESSION_EXPIRE_SECONDS: int = 365 * 3600  # 1 year
    USER_LOGIN_AUTHENTICATOR: str = "jwt_ninja.authenticators.django_user_authenticator"
    JWT_PAYLOAD_CLASS: str = "jwt_ninja.types.JWTPayload"

    model_config = SettingsConfigDict(
        env_prefix="JWT_",
        case_sensitive=True,
    )

    _JWT_PAYLOAD_CLASS: type[JWTPayload]

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

    @property
    def payload_class(self) -> type[JWTPayload]:
        return self._JWT_PAYLOAD_CLASS


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


setting_changed.connect(reload_jwt_settings)
