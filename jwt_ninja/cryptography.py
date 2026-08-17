import time

import jwt
from pydantic import ValidationError

from . import settings as jwt_settings_module
from .errors import JWTExpiredError, JWTInvalidPayloadFormat, JWTInvalidTokenError
from .types import JWTPayload

_TOKEN_TYPES: dict[str, str] = {"access": "at+jwt", "refresh": "rt+jwt"}


def generate_jwt(payload: JWTPayload) -> str:
    """Generate a bounded, profile-conformant signed JWT."""
    config = jwt_settings_module.jwt_settings
    try:
        claims = payload.model_dump(mode="json")
        token_type = claims.get("type")
        if not isinstance(token_type, str) or token_type not in _TOKEN_TYPES:
            raise ValueError("Unsupported token type")
        jose_type = _TOKEN_TYPES[token_type]
        now = int(time.time())
        maximum = config.ACCESS_TOKEN_EXPIRE_SECONDS if token_type == "access" else config.REFRESH_TOKEN_EXPIRE_SECONDS
        exp = claims.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or exp <= now or exp - now > maximum:
            raise ValueError("Token lifetime is outside the configured profile")
        claims.update(iss=config.ISSUER, aud=config.AUDIENCE, iat=now, nbf=now)
        if claims.get("jti") is None:
            claims.pop("jti", None)
        token = jwt.encode(
            payload=claims,
            key=config.SECRET_KEY,
            algorithm=config.ALGORITHM,
            headers={"typ": jose_type},
        )
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise JWTInvalidTokenError() from exc

    if not token or len(token) > config.MAX_TOKEN_LENGTH:
        raise JWTInvalidTokenError()
    return token


def decode_jwt(token: str, payload_class: type[JWTPayload]) -> JWTPayload:
    """Decode a JWT under the configured issuer/audience/type profile."""
    config = jwt_settings_module.jwt_settings
    if not isinstance(token, str) or not token or len(token) > config.MAX_TOKEN_LENGTH:
        raise JWTInvalidTokenError()

    try:
        decoded = jwt.decode_complete(
            jwt=token,
            key=config.verification_key,
            algorithms=[config.ALGORITHM],
            audience=config.AUDIENCE,
            issuer=config.ISSUER,
            leeway=config.LEEWAY_SECONDS,
            options={
                "require": ["exp", "iss", "aud", "iat", "nbf", "type", "user_id", "session_id"],
                "strict_aud": True,
            },
        )
        claims = decoded["payload"]
        token_type = claims.get("type")
        if token_type not in _TOKEN_TYPES or decoded["header"].get("typ") != _TOKEN_TYPES[token_type]:
            raise JWTInvalidTokenError()

        iat = claims["iat"]
        exp = claims["exp"]
        if isinstance(iat, bool) or isinstance(exp, bool):
            raise JWTInvalidTokenError()
        maximum = config.ACCESS_TOKEN_EXPIRE_SECONDS if token_type == "access" else config.REFRESH_TOKEN_EXPIRE_SECONDS
        if exp <= iat or exp - iat > maximum:
            raise JWTInvalidTokenError()
    except jwt.ExpiredSignatureError as exc:
        raise JWTExpiredError() from exc
    except JWTInvalidTokenError:
        raise
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError, OverflowError) as exc:
        raise JWTInvalidTokenError() from exc

    try:
        return payload_class(**claims)
    except ValidationError as exc:
        raise JWTInvalidPayloadFormat() from exc
