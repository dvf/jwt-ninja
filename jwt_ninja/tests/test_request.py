import pytest
from django.http import HttpRequest

from ..request import get_client_ip, get_user_agent, summarize_user_agent


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


def test_get_user_agent_reads_header():
    request = make_request({"HTTP_USER_AGENT": "curl/8.4.0"})
    assert get_user_agent(request) == "curl/8.4.0"


def test_get_user_agent_defaults_to_empty_string():
    request = make_request()
    assert get_user_agent(request) == ""


def test_get_user_agent_truncates_oversized_header():
    request = make_request({"HTTP_USER_AGENT": "A" * 2000})
    assert len(get_user_agent(request)) == 512


@pytest.mark.parametrize(
    ("user_agent", "expected"),
    [
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Chrome on macOS",
        ),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
            "Edge on Windows",
        ),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Firefox on Windows",
        ),
        (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
            "Safari on iOS",
        ),
        (
            "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) CriOS/126.0.6478.54 Mobile/15E148 Safari/604.1",
            "Chrome on iPadOS",
        ),
        (
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
            "Chrome on Android",
        ),
        (
            "Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 "
            "(KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36",
            "Samsung Internet on Android",
        ),
        (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0",
            "Opera on Linux",
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            "Safari on macOS",
        ),
        # Only one half recognized.
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Windows"),
        # Nothing recognized.
        ("curl/8.4.0", None),
        ("python-requests/2.32.0", None),
        ("", None),
        (None, None),
    ],
)
def test_summarize_user_agent(user_agent, expected):
    assert summarize_user_agent(user_agent) == expected
