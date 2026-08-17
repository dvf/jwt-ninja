import pytest
from django.http import HttpRequest
from django.test import override_settings

from ..request import get_client_ip, get_user_agent, summarize_user_agent


def make_request(meta: dict[str, str] | None = None) -> HttpRequest:
    request = HttpRequest()
    request.META = meta or {}
    return request


def test_forwarded_header_is_ignored_without_trusted_peer():
    request = make_request({"REMOTE_ADDR": "198.51.100.2", "HTTP_X_FORWARDED_FOR": "1.1.1.1"})
    assert get_client_ip(request) == "198.51.100.2"


@override_settings(JWT_TRUSTED_PROXY_CIDRS=["10.0.0.0/8"])
def test_get_client_ip_scans_trusted_chain_right_to_left():
    request = make_request({"REMOTE_ADDR": "10.0.0.3", "HTTP_X_FORWARDED_FOR": "1.1.1.1, 10.0.0.1, 10.0.0.2"})
    assert get_client_ip(request) == "1.1.1.1"


@override_settings(JWT_TRUSTED_PROXY_CIDRS=["10.0.0.0/8"])
def test_invalid_forwarded_chain_falls_back_to_remote():
    request = make_request({"REMOTE_ADDR": "10.0.0.3", "HTTP_X_FORWARDED_FOR": "1.1.1.1, bad"})
    assert get_client_ip(request) == "10.0.0.3"


@override_settings(JWT_TRUSTED_PROXY_CIDRS=["10.0.0.0/8"], JWT_MAX_FORWARDED_HOPS=2)
def test_excessive_forwarded_hops_fall_back_to_remote():
    request = make_request({"REMOTE_ADDR": "10.0.0.3", "HTTP_X_FORWARDED_FOR": "1.1.1.1, 10.0.0.1, 10.0.0.2"})
    assert get_client_ip(request) == "10.0.0.3"


def test_get_client_ip_falls_back_to_remote_addr():
    assert get_client_ip(make_request({"REMOTE_ADDR": "3.3.3.3"})) == "3.3.3.3"


def test_get_client_ip_returns_none_when_no_headers():
    assert get_client_ip(make_request()) is None


def test_get_user_agent_reads_header():
    assert get_user_agent(make_request({"HTTP_USER_AGENT": "curl/8.4.0"})) == "curl/8.4.0"


def test_get_user_agent_defaults_to_empty_string():
    assert get_user_agent(make_request()) == ""


def test_get_user_agent_truncates_oversized_header():
    assert len(get_user_agent(make_request({"HTTP_USER_AGENT": "A" * 2000}))) == 512


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
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0", "Firefox on Windows"),
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
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Windows"),
        ("curl/8.4.0", None),
        ("python-requests/2.32.0", None),
        ("", None),
        (None, None),
    ],
)
def test_summarize_user_agent(user_agent, expected):
    assert summarize_user_agent(user_agent) == expected
