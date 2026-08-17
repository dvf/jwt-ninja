import time

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.test import override_settings

import jwt_ninja.settings as jwt_ninja_settings

from ..cryptography import decode_jwt, generate_jwt
from ..settings import jwt_settings
from ..types import JWTPayload


def test_jwt_setting_change_reloads_jwt_settings():
    assert jwt_ninja_settings.jwt_settings.ALGORITHM == "HS256"

    with override_settings(JWT_ALGORITHM="HS512", JWT_SECRET_KEY="x" * 64):
        assert jwt_ninja_settings.jwt_settings.ALGORITHM == "HS512"

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


def test_jwt_refresh_token_transport_reloads(monkeypatch):
    assert jwt_ninja_settings.jwt_settings.REFRESH_TOKEN_TRANSPORT == "body"

    monkeypatch.setenv("JWT_REFRESH_TOKEN_TRANSPORT", "cookie")
    setting_changed.send(sender=None, setting="JWT_REFRESH_TOKEN_TRANSPORT", value="cookie", enter=True)
    assert jwt_ninja_settings.jwt_settings.REFRESH_TOKEN_TRANSPORT == "cookie"

    monkeypatch.delenv("JWT_REFRESH_TOKEN_TRANSPORT")
    setting_changed.send(sender=None, setting="JWT_REFRESH_TOKEN_TRANSPORT", value=None, enter=False)
    assert jwt_ninja_settings.jwt_settings.REFRESH_TOKEN_TRANSPORT == "body"


class CustomPayload(JWTPayload):
    team_id: int = 0


class StrUserIdPayload(JWTPayload):
    user_id: str


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


def test_django_setting_jwt_payload_class_is_honored():
    """
    Setting JWT_PAYLOAD_CLASS via Django settings (override_settings)
    must actually swap the class returned by jwt_settings.payload_class.
    """
    assert jwt_ninja_settings.jwt_settings.payload_class is JWTPayload

    with override_settings(JWT_PAYLOAD_CLASS="jwt_ninja.tests.test_settings.CustomPayload"):
        assert jwt_ninja_settings.jwt_settings.payload_class is CustomPayload

    assert jwt_ninja_settings.jwt_settings.payload_class is JWTPayload


def test_django_setting_jwt_algorithm_is_honored():
    """
    override_settings(JWT_ALGORITHM=...) must propagate to jwt_settings
    without needing to also set JWT_ALGORITHM as an env var.
    """
    assert jwt_ninja_settings.jwt_settings.ALGORITHM == "HS256"

    with override_settings(JWT_ALGORITHM="HS512", JWT_SECRET_KEY="x" * 64):
        assert jwt_ninja_settings.jwt_settings.ALGORITHM == "HS512"

    assert jwt_ninja_settings.jwt_settings.ALGORITHM == "HS256"


@pytest.mark.django_db
def test_django_setting_payload_class_roundtrips_through_generate_decode(test_user, user_session, one_hour_from_now):
    """
    End-to-end: with JWT_PAYLOAD_CLASS set via Django settings, a token
    encoded through generate_jwt decodes back as an instance of the custom
    subclass with its custom claim intact.
    """
    with override_settings(JWT_PAYLOAD_CLASS="jwt_ninja.tests.test_settings.CustomPayload"):
        payload = jwt_settings.payload_class(
            user_id=test_user.id,
            type="access",
            exp=one_hour_from_now,
            session_id=user_session.id,
            team_id=7,
        )
        token = generate_jwt(payload)
        decoded = decode_jwt(token, jwt_settings.payload_class)

    assert isinstance(decoded, CustomPayload)
    assert decoded.team_id == 7


def test_str_user_id_subclass_roundtrips():
    """
    A subclass that overrides user_id: str (e.g., for UUID/CharField
    primary keys on the User model) can be encoded and decoded without
    coercion issues — strings stay strings through JSON/JWT.
    """
    payload = StrUserIdPayload(
        user_id="abc-123",
        type="access",
        exp=int(time.time()) + 300,
        session_id="sess-xyz",
    )
    assert isinstance(payload.user_id, str)

    token = generate_jwt(payload)
    decoded = decode_jwt(token, StrUserIdPayload)

    assert isinstance(decoded, StrUserIdPayload)
    assert decoded.user_id == "abc-123"
    assert isinstance(decoded.user_id, str)


def test_str_user_id_subclass_rejects_int_input():
    """
    Documents the type-safety gotcha called out in the README: passing
    an int to a subclass declaring `user_id: str` fails at construction.
    """
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        StrUserIdPayload(
            user_id=42,  # int, but field is str — pydantic rejects
            type="access",
            exp=9999999999,
            session_id="s",
        )


def test_short_hmac_key_fails_startup():
    with pytest.raises(ImproperlyConfigured, match="at least 32 bytes"):
        with override_settings(JWT_SECRET_KEY="too-short", JWT_ALGORITHM="HS256"):
            pass


def test_missing_dedicated_key_fails_startup():
    with pytest.raises(ImproperlyConfigured, match="explicit, non-empty"):
        with override_settings(JWT_SECRET_KEY=""):
            pass


def test_missing_issuer_or_audience_fails_startup():
    with pytest.raises(ImproperlyConfigured, match="ISSUER and JWT_AUDIENCE"):
        with override_settings(JWT_ISSUER=""):
            pass


def test_distinct_hmac_verifier_fails_startup():
    with pytest.raises(ImproperlyConfigured, match="exactly match"):
        with override_settings(JWT_VERIFYING_KEY="y" * 32):
            pass


def test_hs512_requires_larger_key():
    with pytest.raises(ImproperlyConfigured, match="at least 64 bytes"):
        with override_settings(JWT_SECRET_KEY="x" * 32, JWT_ALGORITHM="HS512"):
            pass


def test_payload_class_must_be_jwt_payload_subclass():
    with pytest.raises(ImproperlyConfigured, match="JWTPayload subclass"):
        with override_settings(JWT_PAYLOAD_CLASS="builtins.str"):
            pass


def test_hmac_rejects_asymmetric_pem_material():
    pem_like = "-----BEGIN PRIVATE KEY-----\n" + ("x" * 64)
    with pytest.raises(ImproperlyConfigured, match="raw secret material"):
        with override_settings(JWT_SECRET_KEY=pem_like, JWT_ALGORITHM="HS256"):
            pass
