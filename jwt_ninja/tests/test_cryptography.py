import base64
import time
from datetime import timedelta
from uuid import UUID, uuid4

import jwt
import pytest
from django.test import override_settings

from ..cryptography import decode_jwt, generate_jwt
from ..errors import JWTExpiredError, JWTInvalidTokenError
from ..settings import jwt_settings
from ..types import JWTPayload


def payload(token_type="access", lifetime=300):
    return JWTPayload(user_id=1, type=token_type, exp=int(time.time()) + lifetime, session_id="abc")


@pytest.mark.parametrize("user_id", [7, "usr_01jq3v", "7"])
def test_user_id_keeps_its_value_and_its_type(user_id):
    """An int key and a str key both work with the stock payload, and a
    numeric string never turns into the integer it looks like."""
    original = JWTPayload(user_id=user_id, type="access", exp=int(time.time()) + 300, session_id="abc")

    decoded = decode_jwt(generate_jwt(original), JWTPayload)

    assert decoded.user_id == user_id
    assert type(decoded.user_id) is type(user_id)


def test_a_uuid_user_id_needs_a_narrowed_payload():
    class UUIDPayload(JWTPayload):
        user_id: UUID

    key = uuid4()
    token = generate_jwt(UUIDPayload(user_id=key, type="access", exp=int(time.time()) + 300, session_id="abc"))

    assert decode_jwt(token, UUIDPayload).user_id == key
    assert decode_jwt(token, JWTPayload).user_id == str(key)


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


def test_explicit_now_avoids_second_boundary_skew():
    fixed_now = int(time.time())
    token = generate_jwt(
        JWTPayload(user_id=1, type="access", exp=fixed_now + 1, session_id="abc"),
        now=fixed_now,
    )
    decoded = decode_jwt(token, JWTPayload)
    assert decoded.iat == fixed_now
    assert decoded.exp == fixed_now + 1


def test_deeply_nested_untrusted_jwt_segment_raises_invalid_token():
    nested = base64.urlsafe_b64encode((b'{"a":' * 1200) + b"1" + (b"}" * 1200)).rstrip(b"=").decode()
    with pytest.raises(JWTInvalidTokenError):
        decode_jwt(f"{nested}.e30.sig", JWTPayload)


@pytest.mark.parametrize("algorithm", ["RS256", "ES256", "EdDSA"])
def test_asymmetric_algorithms_roundtrip(algorithm):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    if algorithm == "RS256":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif algorithm == "ES256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        private_key = ed25519.Ed25519PrivateKey.generate()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )

    with override_settings(
        JWT_ALGORITHM=algorithm,
        JWT_SECRET_KEY=private_pem,
        JWT_VERIFYING_KEY=public_pem,
    ):
        token = generate_jwt(payload())
        decoded = decode_jwt(token, JWTPayload)
        assert decoded.user_id == 1
        assert decoded.session_id == "abc"
