from concurrent.futures import ThreadPoolExecutor
from secrets import token_urlsafe
from threading import Barrier
from typing import Any, cast

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.cache import caches
from django.db import close_old_connections, connection
from django.middleware.csrf import get_token
from django.test import RequestFactory, override_settings
from django.utils import timezone
from pydantic import ValidationError as PydanticValidationError

from ..api import _BrowserBoundaryGuard, login
from ..cryptography import generate_jwt
from ..errors import APIError
from ..models import SecurityStampChangedError, Session, security_stamp_for_user
from ..types import JWTPayload, LoginSchema

User = get_user_model()


class RequiredClaimPayload(JWTPayload):
    team_id: int


@pytest.mark.django_db
def test_unsupported_media_type_is_preparse_and_has_no_state_change(ninja_client, test_user):
    response = ninja_client.post(
        "/auth/login/",
        json={"username": "dan", "password": "dan"},
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == 415
    assert response.json() == {"error_code": "unsupported_media_type"}
    assert Session.objects.count() == 0
    assert response["Cache-Control"] == "no-store"


@pytest.mark.django_db
def test_framework_owned_auth_errors_are_also_no_store(ninja_client):
    responses = [
        ninja_client.post("/auth/login/", data="{"),
        ninja_client.post("/auth/login/", json={"username": "dan"}),
        ninja_client.get("/auth/sessions/"),
    ]

    assert [response.status_code for response in responses] == [400, 422, 401]
    for response in responses:
        assert response["Cache-Control"] == "no-store"
        assert response["Pragma"] == "no-cache"


@pytest.mark.parametrize("content_type", ["application/json; charset=utf-8", "application/problem+json"])
def test_json_media_types_are_accepted_by_preparse_guard(content_type):
    request = RequestFactory().post("/auth/login/", data="{}", content_type=content_type)
    with override_settings(JWT_LOGIN_THROTTLE_RATE=None):
        assert _BrowserBoundaryGuard("login")(request) is True


@pytest.mark.django_db
@override_settings(JWT_REFRESH_TOKEN_TRANSPORT="cookie", JWT_REFRESH_COOKIE_SECURE=False)
def test_cookie_refresh_requires_json_object_body(ninja_client, refresh_token):
    response = ninja_client.post("/auth/refresh/", COOKIES={"refresh_token": refresh_token})
    assert response.status_code == 415
    assert response.json() == {"error_code": "unsupported_media_type"}


@pytest.mark.django_db
@override_settings(JWT_REFRESH_TOKEN_TRANSPORT="cookie", JWT_REFRESH_COOKIE_SECURE=False)
def test_cookie_login_requires_csrf_before_authentication(ninja_client, test_user):
    response = ninja_client.post(
        "/auth/login/",
        json={"username": "dan", "password": "dan"},
        _dont_enforce_csrf_checks=False,
    )

    assert response.status_code == 403
    assert response.json() == {"error_code": "csrf_failed"}
    assert Session.objects.count() == 0


@pytest.mark.django_db
@override_settings(JWT_REFRESH_TOKEN_TRANSPORT="cookie", JWT_REFRESH_COOKIE_SECURE=False)
def test_csrf_bootstrap_allows_cookie_login(ninja_client, test_user):
    bootstrap = ninja_client.get("/auth/csrf/")
    masked = bootstrap.json()["csrf_token"]
    cookie = bootstrap.cookies["csrftoken"].value

    response = ninja_client.post(
        "/auth/login/",
        json={"username": "dan", "password": "dan"},
        headers={"X-CSRFTOKEN": masked},
        COOKIES={"csrftoken": cookie},
        _dont_enforce_csrf_checks=False,
    )

    assert response.status_code == 200
    assert response.cookies["refresh_token"].value


@pytest.mark.django_db
@override_settings(JWT_REFRESH_TOKEN_TRANSPORT="cookie", JWT_REFRESH_COOKIE_SECURE=False)
def test_hostile_origin_fails_csrf_without_auth_state(ninja_client, test_user):
    bootstrap = ninja_client.get("/auth/csrf/")
    response = ninja_client.post(
        "/auth/login/",
        json={"username": "dan", "password": "dan"},
        headers={
            "X-CSRFTOKEN": bootstrap.json()["csrf_token"],
            "ORIGIN": "https://attacker.example",
        },
        COOKIES={"csrftoken": bootstrap.cookies["csrftoken"].value},
        _dont_enforce_csrf_checks=False,
    )

    assert response.status_code == 403
    assert Session.objects.count() == 0


@override_settings(
    JWT_REFRESH_TOKEN_TRANSPORT="cookie",
    JWT_LOGIN_THROTTLE_RATE=None,
    CSRF_TRUSTED_ORIGINS=["https://testserver"],
)
def test_https_trusted_origin_csrf_request_passes_guard():
    request = RequestFactory().post(
        "/auth/login/",
        data="{}",
        content_type="application/json",
        secure=True,
        HTTP_HOST="testserver",
        HTTP_ORIGIN="https://testserver",
    )
    masked = get_token(request)
    cast(Any, request).COOKIES["csrftoken"] = request.META["CSRF_COOKIE"]
    request.META["HTTP_X_CSRFTOKEN"] = masked

    assert _BrowserBoundaryGuard("login")(request) is True


@pytest.mark.django_db
@override_settings(JWT_REFRESH_TOKEN_TRANSPORT="both", JWT_REFRESH_COOKIE_SECURE=False)
def test_both_mode_body_token_cannot_bypass_csrf(ninja_client, refresh_token, user_session):
    before = user_session.refresh_jti
    response = ninja_client.post(
        "/auth/refresh/",
        json={"refresh_token": refresh_token},
        _dont_enforce_csrf_checks=False,
    )

    assert response.status_code == 403
    user_session.refresh_from_db()
    assert user_session.refresh_jti == before
    assert not user_session.is_expired


@pytest.mark.django_db
def test_login_throttle_denies_before_authenticator(ninja_client, mocker):
    authenticator = mocker.patch("jwt_ninja.api.import_string")
    authenticator.return_value.return_value = None
    with override_settings(JWT_LOGIN_THROTTLE_RATE="1/min"):
        first = ninja_client.post("/auth/login/", json={"username": "x", "password": "x"})
        second = ninja_client.post("/auth/login/", json={"username": "x", "password": "x"})

    assert first.status_code == 401
    assert second.status_code == 429
    assert second.json() == {"error_code": "rate_limited"}
    assert int(second["Retry-After"]) > 0
    assert authenticator.return_value.call_count == 1


@pytest.mark.django_db
def test_throttle_cache_failure_fails_closed_before_authenticator(ninja_client, mocker):
    authenticator = mocker.patch("jwt_ninja.api.import_string")
    mocker.patch.object(caches["default"], "add", side_effect=RuntimeError("cache down"))

    response = ninja_client.post("/auth/login/", json={"username": "x", "password": "x"})

    assert response.status_code == 429
    assert response.json() == {"error_code": "rate_limited"}
    authenticator.assert_not_called()


@pytest.mark.django_db
@override_settings(JWT_MAX_ACTIVE_SESSIONS=2)
def test_session_cap_revokes_oldest_deterministically(test_user, freezer):
    first = Session.create_session(test_user, "1.1.1.1")
    freezer.tick()
    second = Session.create_session(test_user, "1.1.1.2")
    freezer.tick()
    third = Session.create_session(test_user, "1.1.1.3")

    first.refresh_from_db()
    second.refresh_from_db()
    third.refresh_from_db()
    assert first.is_expired
    assert not second.is_expired
    assert not third.is_expired
    assert Session.objects.active().filter(user=test_user).count() == 2


@pytest.mark.django_db(transaction=True)
@override_settings(JWT_MAX_ACTIVE_SESSIONS=2)
def test_concurrent_session_creation_keeps_exact_cap(test_user):
    barrier = Barrier(6)

    def create(index):
        close_old_connections()
        try:
            user = User.objects.get(pk=test_user.pk)
            barrier.wait(timeout=5)
            return Session.create_session(user, f"1.1.1.{index + 1}").pk
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=6) as executor:
        ids = list(executor.map(create, range(6)))

    assert len(set(ids)) == 6
    assert Session.objects.active().filter(user=test_user).count() == 2


@pytest.mark.django_db(transaction=True)
def test_postgresql_simultaneous_refresh_consumers_have_one_cas_winner(test_user):
    if connection.vendor != "postgresql":
        pytest.skip("PostgreSQL concurrency regression")

    session = Session.create_session(test_user, "1.1.1.1")
    presented = session.initialize_refresh_jti()
    expected_stamp = session.security_stamp
    assert expected_stamp is not None
    barrier = Barrier(2)

    def consume(_index):
        close_old_connections()
        try:
            barrier.wait(timeout=5)
            return Session.consume_refresh_jti(
                session_id=session.id,
                user_id=test_user.id,
                presented_jti=presented,
                replacement_jti=token_urlsafe(32),
                expected_security_stamp=expected_stamp,
            )[0]
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(consume, range(2)))

    assert sorted(statuses) == ["consumed", "reused"]
    session.refresh_from_db()
    assert session.is_expired


@pytest.mark.django_db
def test_stale_refresh_consumer_cannot_overwrite_cas_winner(user_session, test_user):
    presented = user_session.initialize_refresh_jti()
    assert user_session.security_stamp is not None

    winner_jti = token_urlsafe(32)
    winner = Session.consume_refresh_jti(
        session_id=user_session.id,
        user_id=test_user.id,
        presented_jti=presented,
        replacement_jti=winner_jti,
        expected_security_stamp=user_session.security_stamp,
    )
    stale = Session.consume_refresh_jti(
        session_id=user_session.id,
        user_id=test_user.id,
        presented_jti=presented,
        replacement_jti=token_urlsafe(32),
        expected_security_stamp=user_session.security_stamp,
    )

    assert winner[0] == "consumed"
    assert stale == ("reused", None)
    user_session.refresh_from_db()
    assert user_session.is_expired
    assert user_session.refresh_jti == winner[1]


@pytest.mark.django_db
def test_set_password_revokes_stamped_access_session(ninja_client, access_token, test_user, user_session):
    test_user.set_password("changed")
    test_user.save(update_fields=["password"])

    response = ninja_client.get("/auth/protected/", headers={"Authorization": f"Bearer {access_token}"})

    assert response.status_code == 401
    assert response.json()["error_code"] == "session_expired"
    user_session.refresh_from_db()
    assert user_session.is_expired


@pytest.mark.django_db
def test_bulk_password_hash_change_revokes_refresh_session(ninja_client, refresh_token, test_user, user_session):
    User.objects.filter(pk=test_user.pk).update(password="unusable-bulk-change")

    response = ninja_client.post("/auth/refresh/", json={"refresh_token": refresh_token})

    assert response.status_code == 401
    assert response.json()["error_code"] == "session_expired"
    user_session.refresh_from_db()
    assert user_session.is_expired


@pytest.mark.django_db
def test_auth_hash_callback_failure_revokes_session(ninja_client, access_token, test_user, user_session, mocker):
    mocker.patch.object(test_user, "get_session_auth_hash", side_effect=RuntimeError("callback failed"))
    mocker.patch("jwt_ninja.auth_classes.User.objects.get", return_value=test_user)

    response = ninja_client.get("/auth/protected/", headers={"Authorization": f"Bearer {access_token}"})

    assert response.status_code == 401
    assert response.json()["error_code"] == "session_expired"
    user_session.refresh_from_db()
    assert user_session.is_expired


@pytest.mark.django_db
def test_refresh_wrong_user_does_not_revoke_target_family(ninja_client, test_user, user_session, seven_days_from_now):
    other = User.objects.create_user(username="other-refresh-user", password="secret")
    jti = user_session.initialize_refresh_jti()
    token = generate_jwt(
        JWTPayload(
            user_id=other.id,
            type="refresh",
            exp=seven_days_from_now,
            session_id=user_session.id,
            jti=jti,
        )
    )

    response = ninja_client.post("/auth/refresh/", json={"refresh_token": token})

    assert response.status_code == 401
    assert response.json()["error_code"] == "invalid_token"
    user_session.refresh_from_db()
    assert not user_session.is_expired
    assert user_session.refresh_jti == jti


@pytest.mark.django_db
@override_settings(JWT_REFRESH_TOKEN_TRANSPORT="cookie", JWT_REFRESH_COOKIE_SECURE=False)
def test_logout_revokes_durable_state_before_cookie_cleanup(ninja_client, access_token, mocker):
    events = []

    def revoke(session):
        events.append("revoke")

    def clear(response):
        events.append("cookie")

    mocker.patch.object(Session, "invalidate_session", revoke)
    mocker.patch("jwt_ninja.api._delete_refresh_cookie", clear)

    response = ninja_client.post("/auth/logout/", headers={"Authorization": f"Bearer {access_token}"})

    assert response.status_code == 200
    assert events == ["revoke", "cookie"]


@pytest.mark.django_db
def test_expiry_equality_is_expired(test_user, freezer):
    session = Session.create_session(test_user, "1.1.1.1")
    session.expired_at = timezone.now()
    session.save(update_fields=["expired_at"])

    assert session.is_expired
    assert not Session.objects.active().filter(pk=session.pk).exists()


def test_missing_content_type_is_controlled():
    request = RequestFactory().post("/auth/login/", data=b"{}", content_type="application/json")
    request.META.pop("CONTENT_TYPE", None)
    with pytest.raises(APIError) as exc:
        _BrowserBoundaryGuard("login")(request)
    assert exc.value.error_code == "unsupported_media_type"
    assert exc.value.http_status_code == 415


def test_rate_limit_runs_before_body_materialization(mocker):
    class LazyRequest:
        headers = {"Content-Type": "application/json"}

        @property
        def body(self):
            raise AssertionError("body must not be materialized")

    mocker.patch("jwt_ninja.api._enforce_rate_limit", side_effect=APIError("rate_limited", 429))
    with pytest.raises(APIError) as exc:
        _BrowserBoundaryGuard("login")(LazyRequest())
    assert exc.value.error_code == "rate_limited"


@pytest.mark.django_db
@override_settings(JWT_MAX_ACTIVE_SESSIONS=1)
def test_password_change_between_authentication_and_lock_aborts_without_cap_mutation(test_user, mocker):
    existing = Session.create_session(test_user, "1.1.1.1")
    stale_authenticated_user = test_user
    User.objects.filter(pk=test_user.pk).update(password=make_password("changed"))

    mocker.patch("jwt_ninja.api.import_string", return_value=lambda request, payload: stale_authenticated_user)
    request = RequestFactory().post("/auth/login/", data="{}", content_type="application/json")
    with pytest.raises(APIError) as exc:
        login(request, LoginSchema(username="dan", password="dan"))

    assert exc.value.error_code == "invalid_credentials"
    existing.refresh_from_db()
    assert not existing.is_expired
    assert Session.objects.count() == 1


@pytest.mark.django_db
@override_settings(JWT_MAX_ACTIVE_SESSIONS=1)
def test_login_mint_failure_rolls_back_session_and_cap_eviction(test_user, mocker):
    existing = Session.create_session(test_user, "1.1.1.1")
    mocker.patch("jwt_ninja.api.import_string", return_value=lambda request, payload: test_user)
    mocker.patch("jwt_ninja.api._mint_token_pair", side_effect=RuntimeError("signer unavailable"))
    request = RequestFactory().post("/auth/login/", data="{}", content_type="application/json")

    with pytest.raises(RuntimeError, match="signer unavailable"):
        login(request, LoginSchema(username="dan", password="dan"))

    existing.refresh_from_db()
    assert not existing.is_expired
    assert Session.objects.count() == 1


@pytest.mark.django_db
@override_settings(
    JWT_MAX_ACTIVE_SESSIONS=1,
    JWT_PAYLOAD_CLASS="jwt_ninja.tests.test_runtime_remediation.RequiredClaimPayload",
)
def test_required_custom_claim_failure_rolls_back_login_state(test_user, mocker):
    existing = Session.create_session(test_user, "1.1.1.1")
    mocker.patch("jwt_ninja.api.import_string", return_value=lambda request, payload: test_user)
    request = RequestFactory().post("/auth/login/", data="{}", content_type="application/json")

    with pytest.raises(PydanticValidationError):
        login(request, LoginSchema(username="dan", password="dan"))

    existing.refresh_from_db()
    assert not existing.is_expired
    assert Session.objects.count() == 1


@pytest.mark.django_db
def test_refresh_mint_failure_does_not_consume_current_jti(ninja_client, refresh_token, user_session, mocker):
    before = user_session.refresh_jti
    mocker.patch("jwt_ninja.api._mint_token_pair", side_effect=RuntimeError("signer unavailable"))

    with pytest.raises(RuntimeError, match="signer unavailable"):
        ninja_client.post("/auth/refresh/", json={"refresh_token": refresh_token})

    user_session.refresh_from_db()
    assert user_session.refresh_jti == before
    assert not user_session.is_expired


@pytest.mark.django_db
def test_stale_authenticated_stamp_is_rejected_before_session_creation(test_user):
    authenticated_stamp = security_stamp_for_user(test_user)
    User.objects.filter(pk=test_user.pk).update(password=make_password("changed"))

    with pytest.raises(SecurityStampChangedError):
        Session.create_session(test_user, "1.1.1.1", expected_security_stamp=authenticated_stamp)
    assert not Session.objects.exists()


@pytest.mark.django_db
def test_null_security_stamp_fails_closed_and_expires_session(test_user):
    session = Session.objects.create(user=test_user, security_stamp=None)
    assert not session.security_stamp_matches(test_user)
    session.refresh_from_db()
    assert session.is_expired


def test_openapi_documents_csrf_header_and_validation_response(ninja_client):
    schema = ninja_client.router_or_app.get_openapi_schema(path_prefix="")
    operation = schema["paths"]["/auth/login/"]["post"]
    assert 422 in operation["responses"]
    assert any(parameter["name"] == "X-CSRFToken" for parameter in operation["parameters"])
