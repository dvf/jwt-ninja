from .cryptography import decode_jwt, generate_jwt
from .errors import APIError
from .types import GeoLocation, JWTPayload

__all__ = [
    "APIError",
    "AuthDetails",
    "AuthedRequest",
    "GeoLocation",
    "JWTAuth",
    "JWTPayload",
    "decode_jwt",
    "generate_jwt",
]


def __getattr__(name: str):
    # Lazy re-exports from .auth_classes. Imported on first access so that
    # Django can load jwt_ninja as an app without triggering get_user_model()
    # before the app registry is ready.
    if name in {"AuthDetails", "AuthedRequest", "JWTAuth"}:
        from . import auth_classes

        return getattr(auth_classes, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
