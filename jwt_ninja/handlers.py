from django.http import HttpRequest, JsonResponse

from .errors import APIError


def apply_no_store(response):
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    return response


def error_handler(request: HttpRequest, exc: APIError) -> JsonResponse:
    response = JsonResponse({"error_code": exc.error_code}, status=exc.http_status_code)
    if exc.retry_after is not None:
        response["Retry-After"] = str(exc.retry_after)
    return apply_no_store(response)
