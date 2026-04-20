from django.http import HttpRequest


def get_client_ip(request: HttpRequest) -> str | None:
    """
    Retrieve the client IP address from the given HttpRequest.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        str | None: The client IP address, or None if it cannot be determined.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")
