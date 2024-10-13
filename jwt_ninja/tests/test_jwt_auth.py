import pytest
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.utils import timezone

from ..errors import APIError, JWTExpiredError, JWTInvalidTokenError
from ..models import Session

User = get_user_model()


def create_request(headers: dict[str, str] = None):
    """
    Helper function to create a normal Django HttpRequest
    """
    request = HttpRequest()
    request.META = headers or {}
    return request


@pytest.fixture
def user(mocker):
    return mocker.MagicMock(id=111)


@pytest.fixture
def session(mocker):
    return mocker.MagicMock(id=333, expired_at=None)


@pytest.fixture
def payload(mocker, user, session):
    return mocker.MagicMock(user_id=user.id, session_id=session.id)


@pytest.fixture
def req():
    return create_request()


def test_authenticate_valid_token(req, jwt_auth, user, payload, session, mocker):
    token = "valid_token"

    mocker.patch("jwt_ninja.auth_classes.decode_jwt", return_value=payload)
    mocker.patch("jwt_ninja.auth_classes.User.objects.get", return_value=user)
    mocker.patch("jwt_ninja.auth_classes.Session.objects.get", return_value=session)

    auth_details = jwt_auth.authenticate(req, token)

    assert auth_details.user == user
    assert auth_details.session == session


def test_authenticate_invalid_token(jwt_auth, req, mocker):
    token = "invalid_token"

    mocker.patch("jwt_ninja.auth_classes.decode_jwt", side_effect=JWTInvalidTokenError)
    with pytest.raises(APIError) as exc_info:
        jwt_auth.authenticate(req, token)

    assert exc_info.value.error_code == "invalid_token"
    assert exc_info.value.http_status_code == 401


def test_authenticate_expired_token(jwt_auth, req, mocker):
    token = "expired_token"

    mocker.patch("jwt_ninja.auth_classes.decode_jwt", side_effect=JWTExpiredError)
    with pytest.raises(APIError) as exc_info:
        jwt_auth.authenticate(req, token)

    assert exc_info.value.error_code == "expired_token"
    assert exc_info.value.http_status_code == 401


def test_authenticate_expired_session(
    jwt_auth,
    payload,
    user,
    session,
    req,
    mocker,
    freezer,
):
    token = "valid_token"

    session.expired_at = timezone.now()

    freezer.tick()  # move forward by 1 sec into the future

    mocker.patch("jwt_ninja.auth_classes.decode_jwt", return_value=payload)
    mocker.patch("jwt_ninja.auth_classes.User.objects.get", return_value=user)
    mocker.patch("jwt_ninja.auth_classes.Session.objects.get", return_value=session)
    with pytest.raises(APIError) as exc_info:
        jwt_auth.authenticate(req, token)

    assert exc_info.value.error_code == "session_expired"
    assert exc_info.value.http_status_code == 401


def test_authenticate_session_not_found(jwt_auth, payload, user, req, mocker):
    token = "valid_token"

    # this is the exception we want to simulate
    initial_exc = Session.DoesNotExist

    mocker.patch("jwt_ninja.auth_classes.decode_jwt", return_value=payload)
    mocker.patch("jwt_ninja.auth_classes.User.objects.get", return_value=user)
    mocker.patch("jwt_ninja.auth_classes.Session.objects.get", side_effect=initial_exc)
    with pytest.raises(APIError) as exc_info:
        jwt_auth.authenticate(req, token)

    assert exc_info.value.error_code == "session_not_found"
    assert exc_info.value.http_status_code == 401


def test_authenticate_user_not_found(jwt_auth, mocker, payload, session, req):
    token = "valid_token"

    initial_exc = User.DoesNotExist

    mocker.patch("jwt_ninja.auth_classes.decode_jwt", return_value=payload)
    mocker.patch("jwt_ninja.auth_classes.User.objects.get", side_effect=initial_exc)
    mocker.patch("jwt_ninja.auth_classes.Session.objects.get", return_value=session)
    with pytest.raises(APIError) as exc_info:
        jwt_auth.authenticate(req, token)

    assert exc_info.value.error_code == "invalid_user"
    assert exc_info.value.http_status_code == 401
