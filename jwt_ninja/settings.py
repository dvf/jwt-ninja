from django.conf import settings
from django.core.signals import setting_changed
from django.utils.module_loading import import_string
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class JWTSettings(BaseSettings):
    SECRET_KEY: str = Field(settings.SECRET_KEY)
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

    def __init__(self):
        super().__init__()
        self._USER_LOGIN_AUTHENTICATOR = import_string(self.USER_LOGIN_AUTHENTICATOR)
        self._JWT_PAYLOAD_CLASS = import_string(self.JWT_PAYLOAD_CLASS)


jwt_settings = JWTSettings()


def reload_jwt_settings(*args, **kwargs):
    setting = kwargs["setting"]
    if setting.startswith("JWT_"):
        global jwt_settings
        jwt_settings = JWTSettings()


setting_changed.connect(reload_jwt_settings)
