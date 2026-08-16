from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address
from django.http import HttpRequest


def get_client_ip(request: HttpRequest) -> str | None:
    """
    Retrieve the client IP address from the given HttpRequest.

    `X-Forwarded-For` is set by whatever is in front of Django, but nothing
    stops a client from sending it directly, so the value it yields is only
    trustworthy if a proxy you control overwrites the header. Treat the stored
    address as a hint, not as evidence.

    The result is validated before it is returned: the value lands in a
    GenericIPAddressField, which maps to a Postgres `inet` column, so an
    unvalidated header would raise DataError and fail the login it was
    attached to.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        str | None: The client IP address, or None if it cannot be determined.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        candidate = x_forwarded_for.split(",")[0].strip()
        if _is_ip_address(candidate):
            return candidate

    remote_addr = request.META.get("REMOTE_ADDR")
    if remote_addr and _is_ip_address(remote_addr):
        return remote_addr
    return None


def _is_ip_address(value: str) -> bool:
    try:
        validate_ipv46_address(value)
    except ValidationError:
        return False
    return True


def get_user_agent(request: HttpRequest) -> str:
    """
    The request's raw User-Agent header, or "" if the client sent none.

    Truncated because the value lands in an unbounded text column and the
    header is client-controlled.
    """
    return request.headers.get("User-Agent", "")[:512]


# Substring tables for summarize_user_agent. Order matters: real User-Agent
# strings impersonate each other for compatibility — Edge and Opera contain
# "Chrome", Chrome contains "Safari", iOS devices claim "like Mac OS X" — so
# the more specific marker must be probed first.
_BROWSERS = [
    ("Edg", "Edge"),  # Edg/, EdgA/, EdgiOS/
    ("OPR/", "Opera"),
    ("Opera", "Opera"),
    ("SamsungBrowser", "Samsung Internet"),
    ("Firefox/", "Firefox"),
    ("FxiOS/", "Firefox"),
    ("CriOS/", "Chrome"),
    ("Chrome/", "Chrome"),
    ("Safari/", "Safari"),
]

_PLATFORMS = [
    ("Windows", "Windows"),
    ("iPhone", "iOS"),
    ("iPad", "iPadOS"),
    ("Mac OS X", "macOS"),
    ("Macintosh", "macOS"),
    ("Android", "Android"),
    ("CrOS", "ChromeOS"),
    ("Linux", "Linux"),
]


def summarize_user_agent(user_agent: str | None) -> str | None:
    """
    Best-effort display label for a User-Agent string: "Chrome on macOS".

    Covers the mainstream browsers and platforms; anything unrecognized
    degrades to whichever half was identified, or None. Meant for rendering a
    session list, not for feature detection — clients that need more than this
    get the raw string alongside it.
    """
    if not user_agent:
        return None

    browser = _first_match(user_agent, _BROWSERS)
    platform = _first_match(user_agent, _PLATFORMS)

    if browser and platform:
        return f"{browser} on {platform}"
    return browser or platform


def _first_match(user_agent: str, table: list[tuple[str, str]]) -> str | None:
    for needle, label in table:
        if needle in user_agent:
            return label
    return None
