import base64
import json
import time
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.utils import timezone

from ..cryptography import generate_jwt
from ..models import Session
from ..types import GeoLocation, JWTPayload

User = get_user_model()

CHROME_MAC_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)


def fake_geolocator(ip_address: str) -> GeoLocation:
    """Referenced by dotted path in JWT_GEOLOCATION_PROVIDER override tests."""
    return GeoLocation(city="Reykjavik", country="Iceland", country_code="IS")


@pytest.mark.django_db
def test_login_success_happy(ninja_client, test_user):
    res = ninja_client.post(
        "/auth/login/",
        json={
            "username": "dan",
            "password": "dan",
        },
    )

    assert res.status_code == 200
    json_response = res.json()

    assert "access_token" in json_response
    assert "refresh_token" in json_response

    # Check the contents of the JWT payload
    dec_access_token = json.loads(base64.b64decode(json_response["access_token"].split(".")[1] + "===").decode())
    assert dec_access_token["user_id"] == test_user.id
    assert dec_access_token["type"] == "access"
    assert dec_access_token["session_id"]
    assert dec_access_token["exp"]

    dec_refresh_token = json.loads(base64.b64decode(json_response["refresh_token"].split(".")[1] + "===").decode())
    assert dec_refresh_token["user_id"] == test_user.id
    assert dec_refresh_token["type"] == "refresh"
    assert dec_refresh_token["session_id"] == dec_access_token["session_id"]
    assert dec_refresh_token["exp"]

    assert test_user.jwt_sessions.count() == 1


@pytest.mark.django_db
def test_login_failure(ninja_client):
    res = ninja_client.post(
        "/auth/login/",
        json={
            "username": "wronguser",
            "password": "wrongpass",
        },
    )

    assert res.status_code == 401
    json_response = res.json()
    assert json_response["error_code"] == "invalid_credentials"


@pytest.mark.django_db
def test_refresh_token_success(ninja_client, refresh_token, test_user):
    res = ninja_client.post(
        "/auth/refresh/",
        json={
            "refresh_token": refresh_token,
        },
    )

    assert res.status_code == 200
    json_response = res.json()
    assert "access_token" in json_response

    dec_access_token = json.loads(base64.b64decode(json_response["access_token"].split(".")[1] + "===").decode())
    assert dec_access_token["user_id"] == test_user.id
    assert dec_access_token["type"] == "access"
    assert dec_access_token["exp"]
    assert dec_access_token["session_id"]


@pytest.mark.django_db
@override_settings(
    JWT_REFRESH_TOKEN_TRANSPORT="cookie",
    JWT_REFRESH_COOKIE_SECURE=False,
)
def test_login_sets_refresh_token_cookie_in_cookie_mode(ninja_client, test_user):
    response = ninja_client.post(
        "/auth/login/",
        json={
            "username": "dan",
            "password": "dan",
        },
    )

    assert response.status_code == 200
    json_response = response.json()
    assert "access_token" in json_response
    assert "refresh_token" not in json_response

    refresh_cookie = response.cookies["refresh_token"]
    assert refresh_cookie.value
    assert refresh_cookie["httponly"]
    assert refresh_cookie["path"] == "/auth/refresh/"
    assert refresh_cookie["samesite"] == "Lax"


@pytest.mark.django_db
@override_settings(
    JWT_REFRESH_TOKEN_TRANSPORT="cookie",
    JWT_REFRESH_COOKIE_SECURE=False,
)
def test_refresh_token_reads_from_cookie_in_cookie_mode(ninja_client, refresh_token, test_user):
    response = ninja_client.post(
        "/auth/refresh/",
        json={},
        COOKIES={"refresh_token": refresh_token},
    )

    assert response.status_code == 200
    json_response = response.json()
    assert "access_token" in json_response

    dec_access_token = json.loads(base64.b64decode(json_response["access_token"].split(".")[1] + "===").decode())
    assert dec_access_token["user_id"] == test_user.id
    assert dec_access_token["type"] == "access"


@pytest.mark.django_db
@override_settings(
    JWT_REFRESH_TOKEN_TRANSPORT="both",
    JWT_REFRESH_COOKIE_SECURE=False,
)
def test_login_returns_body_token_and_cookie_in_both_mode(ninja_client, test_user):
    response = ninja_client.post(
        "/auth/login/",
        json={
            "username": "dan",
            "password": "dan",
        },
    )

    assert response.status_code == 200
    json_response = response.json()
    assert "access_token" in json_response
    assert "refresh_token" in json_response
    assert response.cookies["refresh_token"].value == json_response["refresh_token"]


@pytest.mark.django_db
def test_refresh_token_failure_invalid_token(ninja_client):
    response = ninja_client.post(
        "/auth/refresh/",
        json={
            "refresh_token": "invalidtoken",
        },
    )

    assert response.status_code == 401
    json_response = response.json()
    assert "error_code" in json_response
    assert json_response["error_code"] == "invalid_token"


@pytest.mark.django_db
def test_protected_endpoint_success(ninja_client, access_token):
    response = ninja_client.get(
        "/auth/protected/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert response.status_code == 200
    json_response = response.json()
    assert "message" in json_response


@pytest.mark.django_db
def test_protected_endpoint_expired_session(ninja_client, access_token, user_session):
    user_session.expired_at = timezone.now()
    user_session.save()

    response = ninja_client.get(
        "/auth/protected/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert response.status_code == 401
    json_response = response.json()
    assert json_response["error_code"] == "session_expired"


@pytest.mark.django_db
def test_protected_endpoint_fails_with_wrong_token(ninja_client, access_token):
    response = ninja_client.get(
        "/auth/protected/",
        headers={
            "Authorization": f"Bearer {access_token}+1",
        },
    )

    assert response.status_code == 401


@pytest.mark.django_db
def test_protected_endpoint_failure_no_token(ninja_client):
    response = ninja_client.get("/auth/protected/")

    assert response.status_code == 401


@pytest.mark.django_db
def test_access_token_expired(ninja_client, test_user, user_session, freezer):
    payload = JWTPayload(
        user_id=test_user.id,
        type="access",
        exp=int(time.time()) + 1,
        session_id=user_session.id,
    )
    token = generate_jwt(payload)

    # Move 10 secs in the future
    freezer.tick(delta=timedelta(seconds=10))

    response = ninja_client.get(
        "/auth/protected/",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401
    json_response = response.json()
    assert "error_code" in json_response
    assert json_response["error_code"] == "expired_token"


@pytest.mark.django_db
def test_refresh_token_expired(ninja_client, user_session, test_user, freezer):
    payload = JWTPayload(
        user_id=test_user.id,
        type="refresh",
        exp=int(time.time()) + 1,
        session_id=user_session.id,
    )
    token = generate_jwt(payload)

    freezer.tick(delta=timedelta(seconds=10))

    response = ninja_client.post(
        "/auth/refresh/",
        json={
            "refresh_token": token,
        },
    )

    assert response.status_code == 401
    json_response = response.json()
    assert "error_code" in json_response
    assert json_response["error_code"] == "expired_token"


@pytest.mark.django_db
def test_logout(ninja_client, access_token, test_user, user_session):
    response = ninja_client.post(
        "/auth/logout/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    user_session.refresh_from_db()

    assert response.status_code == 200
    assert user_session.expired_at is not None


@pytest.mark.django_db
@override_settings(
    JWT_REFRESH_TOKEN_TRANSPORT="cookie",
    JWT_REFRESH_COOKIE_SECURE=False,
)
def test_logout_clears_refresh_cookie_in_cookie_mode(ninja_client, access_token, user_session):
    response = ninja_client.post(
        "/auth/logout/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    user_session.refresh_from_db()

    assert response.status_code == 200
    assert user_session.expired_at is not None
    assert response.cookies["refresh_token"].value == ""
    assert response.cookies["refresh_token"]["max-age"] == 0


@pytest.mark.django_db
def test_logout_all(ninja_client, access_token, test_user, user_session):
    # Create another active session
    other_session = Session.create_session(user=test_user, ip_address="129.168.7.7")

    response = ninja_client.post(
        "/auth/logout/all/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )
    assert response.status_code == 200

    user_session.refresh_from_db()
    other_session.refresh_from_db()

    assert user_session.expired_at is not None
    assert other_session.expired_at is not None


@pytest.mark.django_db
@override_settings(
    JWT_REFRESH_TOKEN_TRANSPORT="cookie",
    JWT_REFRESH_COOKIE_SECURE=False,
)
def test_logout_all_clears_refresh_cookie_in_cookie_mode(ninja_client, access_token, test_user, user_session):
    other_session = Session.create_session(user=test_user, ip_address="129.168.7.7")

    response = ninja_client.post(
        "/auth/logout/all/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    user_session.refresh_from_db()
    other_session.refresh_from_db()

    assert response.status_code == 200
    assert user_session.expired_at is not None
    assert other_session.expired_at is not None
    assert response.cookies["refresh_token"].value == ""
    assert response.cookies["refresh_token"]["max-age"] == 0


@pytest.mark.django_db
def test_refresh_token_with_access_token_type(ninja_client, access_token):
    response = ninja_client.post(
        "/auth/refresh/",
        json={
            "refresh_token": access_token,
        },
    )

    assert response.status_code == 400
    json_response = response.json()
    assert json_response["error_code"] == "invalid_token_type"


@pytest.mark.django_db
def test_refresh_token_inactive_user(ninja_client, refresh_token, test_user):
    test_user.is_active = False
    test_user.save()

    response = ninja_client.post(
        "/auth/refresh/",
        json={
            "refresh_token": refresh_token,
        },
    )

    assert response.status_code == 401
    json_response = response.json()
    assert json_response["error_code"] == "invalid_user"


@pytest.mark.django_db
def test_refresh_token_deleted_user(ninja_client, refresh_token, test_user):
    test_user.delete()

    response = ninja_client.post(
        "/auth/refresh/",
        json={
            "refresh_token": refresh_token,
        },
    )

    assert response.status_code == 401
    json_response = response.json()
    # Deleting the user cascades to their sessions, so the missing session is
    # what the refresh endpoint notices first.
    assert json_response["error_code"] == "session_not_found"


@pytest.mark.django_db
def test_list_sessions_returns_only_active_sessions_for_current_user(
    ninja_client, access_token, test_user, user_session
):
    expired_session = Session.create_session(user=test_user, ip_address="192.168.1.50")
    expired_session.expired_at = timezone.now() - timedelta(seconds=1)
    expired_session.save()

    other_user = User.objects.create_user(
        email="other@example.com",
        username="other",
        password="other",
    )
    Session.create_session(user=other_user, ip_address="192.168.1.51")

    response = ninja_client.get(
        "/auth/sessions/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert response.status_code == 200
    json_response = response.json()
    assert len(json_response) == 1
    assert json_response[0]["id"] == user_session.id


@pytest.mark.django_db
def test_login_records_user_agent(ninja_client, test_user):
    response = ninja_client.post(
        "/auth/login/",
        json={"username": "dan", "password": "dan"},
        headers={"User-Agent": CHROME_MAC_UA},
    )

    assert response.status_code == 200
    session = test_user.jwt_sessions.get()
    assert session.user_agent == CHROME_MAC_UA
    # No geolocation provider is configured by default, so no location is stored.
    assert session.location is None


@pytest.mark.django_db
@override_settings(JWT_GEOLOCATION_PROVIDER="jwt_ninja.tests.test_api_endpoints.fake_geolocator")
def test_login_records_location_with_configured_provider(ninja_client, test_user):
    response = ninja_client.post(
        "/auth/login/",
        json={"username": "dan", "password": "dan"},
        META={"REMOTE_ADDR": "8.8.8.8"},
    )

    assert response.status_code == 200
    session = test_user.jwt_sessions.get()
    assert session.ip_address == "8.8.8.8"
    assert session.location == {
        "city": "Reykjavik",
        "region": None,
        "country": "Iceland",
        "country_code": "IS",
        "latitude": None,
        "longitude": None,
    }


@pytest.mark.django_db
def test_list_sessions_includes_client_details(ninja_client, access_token, test_user, user_session):
    other_session = Session.create_session(
        user=test_user,
        ip_address="8.8.8.8",
        user_agent=CHROME_MAC_UA,
        location={"city": "Reykjavik", "country": "Iceland", "country_code": "IS"},
    )

    response = ninja_client.get(
        "/auth/sessions/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert response.status_code == 200
    sessions = {row["id"]: row for row in response.json()}
    assert set(sessions) == {user_session.id, other_session.id}

    current = sessions[user_session.id]
    assert current["is_current"] is True
    assert current["user_agent"] is None
    assert current["browser"] is None
    assert current["location"] is None

    other = sessions[other_session.id]
    assert other["is_current"] is False
    assert other["ip_address"] == "8.8.8.8"
    assert other["user_agent"] == CHROME_MAC_UA
    assert other["browser"] == "Chrome on macOS"
    assert other["location"]["city"] == "Reykjavik"
    assert other["location"]["country"] == "Iceland"
    assert other["location"]["country_code"] == "IS"


@pytest.mark.django_db
def test_revoke_session(ninja_client, access_token, test_user, user_session):
    other_session = Session.create_session(user=test_user, ip_address="10.0.0.5")

    response = ninja_client.delete(
        f"/auth/sessions/{other_session.id}/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert response.status_code == 200

    other_session.refresh_from_db()
    user_session.refresh_from_db()
    assert other_session.is_expired
    # The session the request rode on is untouched.
    assert not user_session.is_expired


@pytest.mark.django_db
def test_revoke_session_of_other_user_is_not_found(ninja_client, access_token, user_session):
    other_user = User.objects.create_user(
        email="other@example.com",
        username="other",
        password="other",
    )
    other_session = Session.create_session(user=other_user, ip_address="10.0.0.6")

    response = ninja_client.delete(
        f"/auth/sessions/{other_session.id}/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert response.status_code == 404
    assert response.json()["error_code"] == "session_not_found"

    other_session.refresh_from_db()
    assert not other_session.is_expired


@pytest.mark.django_db
def test_revoke_unknown_session_is_not_found(ninja_client, access_token):
    response = ninja_client.delete(
        "/auth/sessions/does-not-exist/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert response.status_code == 404
    assert response.json()["error_code"] == "session_not_found"


@pytest.mark.django_db
def test_revoke_already_revoked_session_is_not_found(ninja_client, access_token, test_user):
    revoked = Session.create_session(user=test_user, ip_address="10.0.0.7")
    revoked.invalidate_session()

    response = ninja_client.delete(
        f"/auth/sessions/{revoked.id}/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert response.status_code == 404
    assert response.json()["error_code"] == "session_not_found"


@pytest.mark.django_db
@override_settings(
    JWT_REFRESH_TOKEN_TRANSPORT="cookie",
    JWT_REFRESH_COOKIE_SECURE=False,
)
def test_revoke_current_session_clears_refresh_cookie_in_cookie_mode(ninja_client, access_token, user_session):
    response = ninja_client.delete(
        f"/auth/sessions/{user_session.id}/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    user_session.refresh_from_db()

    assert response.status_code == 200
    assert user_session.is_expired
    assert response.cookies["refresh_token"].value == ""
    assert response.cookies["refresh_token"]["max-age"] == 0


@pytest.mark.django_db
def test_protected_endpoint_inactive_user(ninja_client, access_token, test_user):
    test_user.is_active = False
    test_user.save()

    response = ninja_client.get(
        "/auth/protected/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert response.status_code == 401
    json_response = response.json()
    assert json_response["error_code"] == "invalid_user"
