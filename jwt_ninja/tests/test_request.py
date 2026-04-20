from django.http import HttpRequest

from ..request import get_client_ip


def make_request(meta: dict[str, str] | None = None) -> HttpRequest:
    request = HttpRequest()
    request.META = meta or {}
    return request


def test_get_client_ip_single_x_forwarded_for():
    request = make_request({"HTTP_X_FORWARDED_FOR": "1.1.1.1"})
    assert get_client_ip(request) == "1.1.1.1"


def test_get_client_ip_multiple_x_forwarded_for():
    request = make_request({"HTTP_X_FORWARDED_FOR": "1.1.1.1,2.2.2.2"})
    assert get_client_ip(request) == "1.1.1.1"


def test_get_client_ip_x_forwarded_for_with_whitespace():
    request = make_request({"HTTP_X_FORWARDED_FOR": "  1.1.1.1 , 2.2.2.2"})
    assert get_client_ip(request) == "1.1.1.1"


def test_get_client_ip_falls_back_to_remote_addr():
    request = make_request({"REMOTE_ADDR": "3.3.3.3"})
    assert get_client_ip(request) == "3.3.3.3"


def test_get_client_ip_returns_none_when_no_headers():
    request = make_request()
    assert get_client_ip(request) is None
