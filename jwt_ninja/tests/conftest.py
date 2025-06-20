import time

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from ninja import NinjaAPI
from ninja.testing import TestClient

from ..api import router
from ..auth_classes import AuthedRequest, JWTAuth
from ..cryptography import generate_jwt
from ..errors import APIError
from ..handlers import error_handler
from ..models import Session
from ..types import JWTPayload

User = get_user_model()


@pytest.fixture
def jwt_auth():
    return JWTAuth()


@pytest.fixture(scope="session")
def ninja_client() -> TestClient:
    def sample_view(request: AuthedRequest):
        return {"message": "secret_th1ngs"}

    api = NinjaAPI()
    api.add_router("auth/", router)
    api.api_operation(["GET"], "auth/protected/", auth=JWTAuth())(sample_view)
    api.exception_handler(APIError)(error_handler)

    return TestClient(api)


@pytest.fixture
def test_user() -> User:
    return User.objects.create_user(
        email="dan@example.com",
        username="dan",
        password="dan",
    )


@pytest.fixture
def one_hour_from_now() -> int:
    return int(time.time()) + 3600


@pytest.fixture
def seven_days_from_now() -> int:
    return int(time.time()) + 7 * 24 * 3600


@pytest.fixture
def user_session(test_user) -> Session:
    """
    Fixture to generate a valid session token for the test user.
    """
    return Session.create_session(user=test_user, ip_address="192.168.1.99")


@pytest.fixture
def access_token(test_user, user_session, one_hour_from_now) -> str:
    """
    Fixture to generate a valid access token for the test user.
    """
    payload = JWTPayload(
        user_id=test_user.id,
        type="access",
        exp=one_hour_from_now,
        session_id=user_session.id,
    )
    return generate_jwt(payload)


@pytest.fixture
def expired_sessions(test_user, user_session, freezer) -> list[Session]:
    """
    Fixture to generate expired sessions for the user.
    """
    freezer.move_to("2022-01-01 12:00:00")
    timestamp = timezone.now()

    return [
        Session.objects.create(
            user=test_user,
            created_at=timestamp,
            updated_at=timestamp,
            expired_at=timestamp,
            ip_address="192.168.1.1",
        ),
        Session.objects.create(
            user=test_user,
            created_at=timestamp,
            updated_at=timestamp,
            expired_at=timestamp,
            ip_address="192.168.1.2",
        ),
    ]


@pytest.fixture
def refresh_token(test_user, user_session, seven_days_from_now) -> str:
    """
    Fixture to generate a valid refresh token for the test user.
    """
    payload = JWTPayload(
        user_id=test_user.id,
        type="refresh",
        exp=seven_days_from_now,
        session_id=user_session.id,
    )
    return generate_jwt(payload)
