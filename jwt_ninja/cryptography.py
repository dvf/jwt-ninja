from typing import Type

import jwt
from pydantic import ValidationError

from .errors import JWTExpiredError, JWTInvalidPayloadFormat, JWTInvalidTokenError
from .settings import jwt_settings
from .types import JWTPayload


def generate_jwt(payload: JWTPayload) -> str:
    """
    Generates a JSON Web Token (JWT)

    Args:
        payload (JWTPayload): The data to include in the token payload.

    Returns:
        str: The encoded JWT as a string.
    """
    return jwt.encode(
        payload=payload.model_dump(mode="json"),
        key=jwt_settings.SECRET_KEY,
        algorithm=jwt_settings.ALGORITHM,
    )


def decode_jwt(token: str, payload_class: Type[JWTPayload]) -> JWTPayload:
    """
    Decodes a JSON Web Token (JWT) and returns the payload.

    Args:
        token (str): The encoded JWT as a string.
        payload_class (Type[JWTPayload]): The class to deserialize the payload into.

    Returns:
        JWTPayload: The deserialized payload.

    Raises:
        JWTExpiredError: If the token has expired.
        JWTInvalidTokenError: If the token is invalid.
        JWTInvalidPayloadFormat: If the payload format is invalid.
    """
    try:
        payload = jwt.decode(
            jwt=token,
            key=jwt_settings.SECRET_KEY,
            algorithms=[jwt_settings.ALGORITHM],
        )

    except jwt.ExpiredSignatureError as err:
        raise JWTExpiredError() from err

    except jwt.InvalidTokenError as err:
        raise JWTInvalidTokenError() from err

    try:
        return payload_class(**payload)
    except ValidationError as exc:
        raise JWTInvalidPayloadFormat() from exc
