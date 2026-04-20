import pytest
from django.core.signals import setting_changed
from django.test import override_settings

import jwt_ninja.settings as jwt_ninja_settings

from ..cryptography import decode_jwt, generate_jwt
from ..settings import jwt_settings
from ..types import JWTPayload


def test_jwt_setting_change_reloads_jwt_settings(monkeypatch):
    assert jwt_ninja_settings.jwt_settings.ALGORITHM == "HS256"

    monkeypatch.setenv("JWT_ALGORITHM", "HS512")
    setting_changed.send(sender=None, setting="JWT_ALGORITHM", value="HS512", enter=True)
    assert jwt_ninja_settings.jwt_settings.ALGORITHM == "HS512"

    monkeypatch.delenv("JWT_ALGORITHM")
    setting_changed.send(sender=None, setting="JWT_ALGORITHM", value=None, enter=False)
    assert jwt_ninja_settings.jwt_settings.ALGORITHM == "HS256"


def test_non_jwt_setting_change_does_not_reload_jwt_settings():
    original_id = id(jwt_ninja_settings.jwt_settings)
    with override_settings(LANGUAGE_CODE="fr"):
        assert id(jwt_ninja_settings.jwt_settings) == original_id
    assert id(jwt_ninja_settings.jwt_settings) == original_id


def test_jwt_access_token_expire_seconds_reloads(monkeypatch):
    assert jwt_ninja_settings.jwt_settings.ACCESS_TOKEN_EXPIRE_SECONDS == 300

    monkeypatch.setenv("JWT_ACCESS_TOKEN_EXPIRE_SECONDS", "42")
    setting_changed.send(sender=None, setting="JWT_ACCESS_TOKEN_EXPIRE_SECONDS", value=42, enter=True)
    assert jwt_ninja_settings.jwt_settings.ACCESS_TOKEN_EXPIRE_SECONDS == 42

    monkeypatch.delenv("JWT_ACCESS_TOKEN_EXPIRE_SECONDS")
    setting_changed.send(sender=None, setting="JWT_ACCESS_TOKEN_EXPIRE_SECONDS", value=None, enter=False)
    assert jwt_ninja_settings.jwt_settings.ACCESS_TOKEN_EXPIRE_SECONDS == 300


class CustomPayload(JWTPayload):
    team_id: int


@pytest.mark.django_db
def test_custom_payload_class_is_used(test_user, user_session, one_hour_from_now, monkeypatch):
    """
    Verifies the JWT_PAYLOAD_CLASS setting is wired through the encode/decode
    call sites: a custom subclass round-trips its extra claim.
    """
    monkeypatch.setattr(jwt_settings, "_JWT_PAYLOAD_CLASS", CustomPayload)
    assert jwt_settings.payload_class is CustomPayload

    payload = jwt_settings.payload_class(
        user_id=test_user.id,
        type="access",
        exp=one_hour_from_now,
        session_id=user_session.id,
        team_id=42,
    )
    token = generate_jwt(payload)

    decoded = decode_jwt(token, jwt_settings.payload_class)

    assert isinstance(decoded, CustomPayload)
    assert decoded.team_id == 42
    assert decoded.user_id == test_user.id
    assert decoded.session_id == user_session.id
