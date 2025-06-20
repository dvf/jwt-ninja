import base64
import json
import time
from datetime import timedelta

import pytest
from django.utils import timezone

from ..cryptography import generate_jwt
from ..models import Session
from ..types import JWTPayload


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
