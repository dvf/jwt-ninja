"""
Regression tests for the authentication invariants the library depends on.

Each test here corresponds to a way tokens or sessions could previously be
used for something they were not issued for.
"""

import time

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, override_settings
from django.utils import timezone

from ..cryptography import generate_jwt
from ..errors import JWTInvalidTokenError
from ..models import Session
from ..request import get_client_ip
from ..types import JWTPayload


@pytest.mark.django_db
def test_refresh_token_is_rejected_on_protected_routes(ninja_client, refresh_token):
    """
    Refresh tokens are long-lived and, under cookie transport, scoped to the
    refresh path. They must not authenticate a protected route.
    """
    response = ninja_client.get(
        "/auth/protected/",
        headers={"Authorization": f"Bearer {refresh_token}"},
    )

    assert response.status_code == 401
    assert response.json()["error_code"] == "invalid_token_type"


@pytest.mark.django_db
def test_access_token_for_another_users_session_is_rejected(ninja_client, test_user, one_hour_from_now):
    """
    `session_id` and `user_id` are independent claims; a token pairing them
    differently than the database does was not issued by us.
    """
    User = type(test_user)
    other_user = User.objects.create_user(username="mallory", email="m@example.com", password="m")
    other_session = Session.create_session(user=other_user, ip_address="1.2.3.4")

    token = generate_jwt(
        JWTPayload(
            user_id=test_user.id,
            type="access",
            exp=one_hour_from_now,
            session_id=other_session.id,
        )
    )

    response = ninja_client.get("/auth/protected/", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.json()["error_code"] == "invalid_token"


@pytest.mark.django_db
def test_refresh_is_rejected_after_logout(ninja_client, refresh_token, user_session):
    """
    Logging out must end the refresh path too, not just the access path.
    """
    user_session.invalidate_session()

    response = ninja_client.post("/auth/refresh/", json={"refresh_token": refresh_token})

    assert response.status_code == 401
    assert response.json()["error_code"] == "session_expired"


@pytest.mark.django_db
def test_refresh_is_rejected_after_session_is_purged(ninja_client, refresh_token, user_session):
    Session.objects.filter(id=user_session.id).delete()

    response = ninja_client.post("/auth/refresh/", json={"refresh_token": refresh_token})

    assert response.status_code == 401
    assert response.json()["error_code"] == "session_not_found"


@pytest.mark.django_db
def test_refresh_rotates_the_refresh_token(ninja_client, refresh_token):
    response = ninja_client.post("/auth/refresh/", json={"refresh_token": refresh_token})

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["refresh_token"] != refresh_token


@pytest.mark.django_db
@override_settings(JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS=0)
def test_replaying_a_rotated_token_revokes_the_session(ninja_client, refresh_token, user_session):
    """
    With no grace window, presenting a superseded refresh token is treated as
    a stolen-token replay and takes the whole session down.
    """
    first = ninja_client.post("/auth/refresh/", json={"refresh_token": refresh_token})
    assert first.status_code == 200

    replay = ninja_client.post("/auth/refresh/", json={"refresh_token": refresh_token})

    assert replay.status_code == 401
    assert replay.json()["error_code"] == "token_reuse_detected"

    user_session.refresh_from_db()
    assert user_session.is_expired is True

    # The token minted by the legitimate first refresh dies with the session.
    followup = ninja_client.post("/auth/refresh/", json={"refresh_token": first.json()["refresh_token"]})
    assert followup.status_code == 401


def test_positive_grace_window_is_rejected():
    with pytest.raises(ImproperlyConfigured, match="must be 0"):
        with override_settings(JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS=30):
            pass


@pytest.mark.django_db
def test_unknown_jti_revokes_the_session(ninja_client, user_session, test_user, seven_days_from_now):
    """
    A well-signed refresh token naming a jti this session never issued.
    """
    user_session.initialize_refresh_jti()
    token = generate_jwt(
        JWTPayload(
            user_id=test_user.id,
            type="refresh",
            exp=seven_days_from_now,
            session_id=user_session.id,
            jti="a-jti-this-session-never-issued",
        )
    )

    response = ninja_client.post("/auth/refresh/", json={"refresh_token": token})

    assert response.status_code == 401
    assert response.json()["error_code"] == "token_reuse_detected"
    user_session.refresh_from_db()
    assert user_session.is_expired is True


@pytest.mark.django_db
def test_pre_rotation_refresh_token_is_rejected_without_adoption(ninja_client, legacy_refresh_token, user_session):
    response = ninja_client.post("/auth/refresh/", json={"refresh_token": legacy_refresh_token})

    assert response.status_code == 401
    assert response.json()["error_code"] == "invalid_token"
    user_session.refresh_from_db()
    assert user_session.refresh_jti is None


@pytest.mark.django_db
def test_sessions_are_created_with_an_expiry(test_user):
    session = Session.create_session(user=test_user, ip_address="1.2.3.4")

    assert session.expired_at is not None
    assert session.expired_at > timezone.now()


@pytest.mark.django_db
@override_settings(JWT_SESSION_EXPIRE_SECONDS=0)
def test_session_expiry_can_be_disabled(test_user):
    session = Session.create_session(user=test_user, ip_address="1.2.3.4")

    assert session.expired_at is None
    assert session.is_expired is False


@pytest.mark.django_db
def test_aged_out_session_does_not_authenticate(ninja_client, test_user, one_hour_from_now):
    session = Session.create_session(user=test_user, ip_address="1.2.3.4")
    session.expired_at = timezone.now() - timezone.timedelta(seconds=1)
    session.save()

    token = generate_jwt(
        JWTPayload(
            user_id=test_user.id,
            type="access",
            exp=one_hour_from_now,
            session_id=session.id,
        )
    )

    response = ninja_client.get("/auth/protected/", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.json()["error_code"] == "session_expired"


@pytest.mark.django_db
def test_aged_out_sessions_are_not_listed_as_active(ninja_client, access_token, test_user, user_session):
    stale = Session.create_session(user=test_user, ip_address="9.9.9.9")
    stale.expired_at = timezone.now() - timezone.timedelta(seconds=1)
    stale.save()

    response = ninja_client.get("/auth/sessions/", headers={"Authorization": f"Bearer {access_token}"})

    assert response.status_code == 200
    assert [s["id"] for s in response.json()] == [user_session.id]


@pytest.mark.django_db
def test_sessions_endpoint_handles_a_null_ip(ninja_client, access_token, user_session):
    user_session.ip_address = None
    user_session.save()

    response = ninja_client.get("/auth/sessions/", headers={"Authorization": f"Bearer {access_token}"})

    assert response.status_code == 200
    assert response.json()[0]["ip_address"] is None


def test_spoofed_forwarded_header_is_not_stored_when_malformed():
    """
    The value reaches a GenericIPAddressField, which is an `inet` column on
    Postgres — an unvalidated header would fail the login it rode in on.
    """
    request = RequestFactory().post("/auth/login/", HTTP_X_FORWARDED_FOR="'; DROP TABLE--")

    assert get_client_ip(request) == "127.0.0.1"


def test_oversized_forwarded_header_is_not_stored():
    request = RequestFactory().post("/auth/login/", HTTP_X_FORWARDED_FOR="A" * 5000)

    assert get_client_ip(request) == "127.0.0.1"


def test_client_ip_is_none_when_nothing_is_resolvable():
    request = RequestFactory().post("/auth/login/")
    del request.META["REMOTE_ADDR"]

    assert get_client_ip(request) is None


@pytest.mark.django_db
def test_login_survives_a_malformed_forwarded_header(ninja_client, test_user):
    """
    A single header must not be able to fail every login. Note the META key is
    supplied directly: ninja's TestClient doesn't upper-case header names the
    way WSGI does, so `headers={"X-Forwarded-For": ...}` would never be read.
    """
    response = ninja_client.post(
        "/auth/login/",
        json={"username": "dan", "password": "dan"},
        META={"REMOTE_ADDR": "127.0.0.1", "HTTP_X_FORWARDED_FOR": "not-an-ip"},
    )

    assert response.status_code == 200
    session = Session.objects.get(user=test_user)
    assert session.ip_address == "127.0.0.1"


@pytest.mark.django_db
@override_settings(JWT_TRUSTED_PROXY_CIDRS=["127.0.0.0/8", "10.0.0.0/8"])
def test_login_records_a_forwarded_ip_when_it_is_valid(ninja_client, test_user):
    response = ninja_client.post(
        "/auth/login/",
        json={"username": "dan", "password": "dan"},
        META={"REMOTE_ADDR": "127.0.0.1", "HTTP_X_FORWARDED_FOR": "203.0.113.7, 10.0.0.1"},
    )

    assert response.status_code == 200
    session = Session.objects.get(user=test_user)
    assert session.ip_address == "203.0.113.7"


def test_none_algorithm_is_rejected():
    # Misconfiguration surfaces as soon as the setting is applied.
    with pytest.raises(ImproperlyConfigured, match="cannot be 'none'"):
        with override_settings(JWT_ALGORITHM="none"):
            pass


def test_unknown_algorithm_is_rejected():
    with pytest.raises(ImproperlyConfigured, match="unavailable"):
        with override_settings(JWT_ALGORITHM="HS1"):
            pass


def test_token_without_exp_is_rejected():
    """
    PyJWT only enforces `exp` when present, so a custom payload class that
    made it optional would otherwise mint non-expiring tokens.
    """

    class NoExpPayload(JWTPayload):
        exp: int | None = None

    with pytest.raises(JWTInvalidTokenError):
        generate_jwt(NoExpPayload(user_id=1, type="access", session_id="s", exp=None))


def test_expired_access_token_is_not_generated():
    with pytest.raises(JWTInvalidTokenError):
        generate_jwt(JWTPayload(user_id=1, type="access", exp=int(time.time()) - 1, session_id="whatever"))
