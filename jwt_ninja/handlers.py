from django.http import HttpRequest, JsonResponse

from .errors import APIError


def error_handler(request: HttpRequest, exc: APIError):
    return JsonResponse(
        {"error_code": exc.error_code},
        status=exc.http_status_code,
    )
