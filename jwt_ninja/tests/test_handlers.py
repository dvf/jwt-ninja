import json

import pytest
from django.http import HttpRequest

from ..errors import APIError
from ..handlers import error_handler


@pytest.mark.parametrize(
    ("error_code", "http_status_code"),
    [
        ("invalid_credentials", 401),
        ("invalid_token_type", 400),
        ("session_expired", 401),
    ],
)
def test_error_handler_returns_json_response(error_code, http_status_code):
    request = HttpRequest()
    exc = APIError(error_code, http_status_code)

    response = error_handler(request, exc)

    assert response.status_code == http_status_code
    assert json.loads(response.content) == {"error_code": error_code}
    assert response["Content-Type"] == "application/json"
