from django.http import HttpRequest


def get_client_ip(request: HttpRequest) -> str:
    """
    Retrieve the client IP address from the given HttpRequest.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        str: The client IP address.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    else:
        return request.META.get("REMOTE_ADDR")
