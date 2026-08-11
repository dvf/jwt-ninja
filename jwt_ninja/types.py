from datetime import datetime
from typing import Generic, Literal, TypeVar

from ninja import Schema
from pydantic import BaseModel, Field


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


class SessionResponse(Schema):
    id: str
    created_at: datetime
    last_activity_at: datetime = Field(alias="updated_at")
    # Nullable on the model: the client IP is unknown when the request carries
    # neither REMOTE_ADDR nor a usable forwarded header.
    ip_address: str | None
