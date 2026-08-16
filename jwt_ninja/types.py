from datetime import datetime
from typing import Generic, Literal, TypeVar

from ninja import Schema
from pydantic import BaseModel, Field

from .request import summarize_user_agent


class JWTPayload(BaseModel):
    type: Literal["access", "refresh"]
    exp: int

    # Identifies a specific refresh token so it can be rotated and replays
    # detected. Absent on access tokens, and on refresh tokens issued before
    # rotation was introduced.
    jti: str | None = None

    # Custom claims
    user_id: int
    session_id: str


class LoginSchema(BaseModel):
    username: str
    password: str


class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str | None = None


class RefreshTokenSchema(BaseModel):
    refresh_token: str | None = None


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

    city: str | None = None
    region: str | None = None
    country: str | None = None
    country_code: str | None = None
    latitude: float | None = None
    longitude: float | None = None


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
