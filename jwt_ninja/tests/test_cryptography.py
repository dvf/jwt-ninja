import time
from datetime import timedelta

import jwt
import pytest

from ..cryptography import decode_jwt, generate_jwt
from ..errors import JWTExpiredError, JWTInvalidPayloadFormat, JWTInvalidTokenError
from ..settings import jwt_settings
from ..types import JWTPayload


def test_roundtrip_preserves_fields():
    payload = JWTPayload(
        user_id=1,
        type="access",
        exp=int(time.time()) + 3600,
        session_id="abc",
    )
    token = generate_jwt(payload)

    decoded = decode_jwt(token, JWTPayload)

    assert decoded.user_id == payload.user_id
    assert decoded.type == payload.type
    assert decoded.exp == payload.exp
    assert decoded.session_id == payload.session_id


def test_expired_token_raises(freezer):
    payload = JWTPayload(
        user_id=1,
        type="access",
        exp=int(time.time()) + 1,
        session_id="abc",
    )
    token = generate_jwt(payload)

    freezer.tick(delta=timedelta(seconds=10))

    with pytest.raises(JWTExpiredError):
        decode_jwt(token, JWTPayload)


def test_tampered_signature_raises():
    payload = JWTPayload(
        user_id=1,
        type="access",
        exp=int(time.time()) + 3600,
        session_id="abc",
    )
    token = generate_jwt(payload)
    tampered = token.rsplit(".", 1)[0] + ".mangled"

    with pytest.raises(JWTInvalidTokenError):
        decode_jwt(tampered, JWTPayload)


def test_wrong_secret_raises(monkeypatch):
    payload = JWTPayload(
        user_id=1,
        type="access",
        exp=int(time.time()) + 3600,
        session_id="abc",
    )
    token = generate_jwt(payload)

    monkeypatch.setattr(jwt_settings, "SECRET_KEY", "other-key")
    with pytest.raises(JWTInvalidTokenError):
        decode_jwt(token, JWTPayload)


def test_malformed_payload_missing_field_raises():
    malformed = jwt.encode(
        {"type": "access", "exp": int(time.time()) + 3600},
        jwt_settings.SECRET_KEY,
        algorithm=jwt_settings.ALGORITHM,
    )

    with pytest.raises(JWTInvalidPayloadFormat):
        decode_jwt(malformed, JWTPayload)


def test_malformed_payload_wrong_type_value_raises():
    malformed = jwt.encode(
        {
            "type": "bogus",
            "exp": int(time.time()) + 3600,
            "user_id": 1,
            "session_id": "abc",
        },
        jwt_settings.SECRET_KEY,
        algorithm=jwt_settings.ALGORITHM,
    )

    with pytest.raises(JWTInvalidPayloadFormat):
        decode_jwt(malformed, JWTPayload)
