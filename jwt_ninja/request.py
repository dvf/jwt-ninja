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
