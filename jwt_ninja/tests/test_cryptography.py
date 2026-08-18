import time
from datetime import timedelta

import jwt
import pytest

from ..cryptography import decode_jwt, generate_jwt
from ..errors import JWTExpiredError, JWTInvalidTokenError
from ..settings import jwt_settings
from ..types import JWTPayload


def payload(token_type="access", lifetime=300):
    return JWTPayload(user_id=1, type=token_type, exp=int(time.time()) + lifetime, session_id="abc")


def test_roundtrip_preserves_fields_and_registered_claims():
    original = payload()
    token = generate_jwt(original)
    decoded = decode_jwt(token, JWTPayload)

    assert decoded.user_id == original.user_id
    assert decoded.type == original.type
    assert decoded.session_id == original.session_id
    assert decoded.iss == jwt_settings.ISSUER
    assert decoded.aud == jwt_settings.AUDIENCE
    assert decoded.iat is not None
    assert decoded.nbf == decoded.iat
    assert jwt.get_unverified_header(token)["typ"] == "at+jwt"


def test_expired_token_raises(freezer):
    token = generate_jwt(payload(lifetime=1))
    freezer.tick(delta=timedelta(seconds=10))
    with pytest.raises(JWTExpiredError):
        decode_jwt(token, JWTPayload)


def test_tampered_signature_raises():
    token = generate_jwt(payload())
    with pytest.raises(JWTInvalidTokenError):
        decode_jwt(token.rsplit(".", 1)[0] + ".mangled", JWTPayload)


def test_wrong_secret_raises(monkeypatch):
    token = generate_jwt(payload())
    monkeypatch.setattr(jwt_settings, "SECRET_KEY", "other-key-that-is-at-least-thirty-two-bytes")
    with pytest.raises(JWTInvalidTokenError):
        decode_jwt(token, JWTPayload)


def test_missing_required_profile_claim_is_rejected():
    malformed = jwt.encode(
        {"type": "access", "exp": int(time.time()) + 300, "user_id": 1, "session_id": "abc"},
        jwt_settings.SECRET_KEY,
        algorithm=jwt_settings.ALGORITHM,
        headers={"typ": "at+jwt"},
    )
    with pytest.raises(JWTInvalidTokenError):
        decode_jwt(malformed, JWTPayload)


def test_wrong_jose_type_is_rejected():
    now = int(time.time())
    malformed = jwt.encode(
        {
            "type": "access",
            "exp": now + 300,
            "iat": now,
            "nbf": now,
            "iss": jwt_settings.ISSUER,
            "aud": jwt_settings.AUDIENCE,
            "user_id": 1,
            "session_id": "abc",
        },
        jwt_settings.SECRET_KEY,
        algorithm=jwt_settings.ALGORITHM,
        headers={"typ": "rt+jwt"},
    )
    with pytest.raises(JWTInvalidTokenError):
        decode_jwt(malformed, JWTPayload)


def test_oversized_lifetime_is_rejected_at_generation():
    with pytest.raises(JWTInvalidTokenError):
        generate_jwt(payload(lifetime=301))
