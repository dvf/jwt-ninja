from datetime import datetime
from typing import Generic, Literal, TypeVar

from ninja import Schema
from pydantic import BaseModel, Field

from .request import summarize_user_agent


class JWTPayload(BaseModel):
    type: Literal["access", "refresh"]
    exp: int
    # These registered claims are injected by generate_jwt. Keeping defaults
    # lets custom payload subclasses continue to construct domain claims only.
    iss: str | None = None
    aud: str | None = None
    iat: int | None = None
    nbf: int | None = None

    jti: str | None = None

    # Custom claims
    user_id: int
    session_id: str


class LoginSchema(BaseModel):
    username: str = Field(min_length=1, max_length=1024)
    password: str = Field(min_length=1, max_length=65536)


class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str | None = None


class RefreshTokenSchema(BaseModel):
    refresh_token: str | None = Field(default=None, max_length=65536)


E = TypeVar("E", bound=str)


class ErrorResponseType(BaseModel, Generic[E]):
    error_code: E


class GeoLocation(BaseModel):
    """
    Where an IP address appears to be.

    Returned by the callable configured as JWT_GEOLOCATION_PROVIDER and stored
    on the session at login. Every field is optional because providers differ
    in how much they can resolve for a given address.
    """

    city: str | None = Field(default=None, max_length=128)
    region: str | None = Field(default=None, max_length=128)
    country: str | None = Field(default=None, max_length=128)
    country_code: str | None = Field(default=None, min_length=2, max_length=2)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)


class SessionResponse(Schema):
    id: str
    created_at: datetime
    last_activity_at: datetime = Field(alias="updated_at")
    # Nullable on the model: the client IP is unknown when the request carries
    # neither REMOTE_ADDR nor a usable forwarded header.
    ip_address: str | None
    user_agent: str | None = None
    browser: str | None = None
    location: GeoLocation | None = None
    is_current: bool = False

    @staticmethod
    def resolve_user_agent(obj) -> str | None:
        return obj.user_agent or None

    @staticmethod
    def resolve_browser(obj) -> str | None:
        return summarize_user_agent(obj.user_agent)

    @staticmethod
    def resolve_is_current(obj, context) -> bool:
        # The session list is rendered for a picker of "which devices am I
        # signed in on"; the client needs to know which row would sign it out.
        request = (context or {}).get("request")
        session = getattr(getattr(request, "auth", None), "session", None)
        return session is not None and session.id == obj.id
