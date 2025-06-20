from datetime import datetime
from typing import Generic, Literal, TypeVar

from ninja import Schema
from pydantic import BaseModel, Field


class JWTPayload(BaseModel):
    type: Literal["access", "refresh"]
    exp: int

    # Custom claims
    user_id: int
    session_id: str


class LoginSchema(BaseModel):
    username: str
    password: str


class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str


class RefreshTokenSchema(BaseModel):
    refresh_token: str


class AccessTokenSchema(BaseModel):
    access_token: str


E = TypeVar("E", bound=str)


class ErrorResponseType(BaseModel, Generic[E]):
    error_code: E


class SessionResponse(Schema):
    id: str
    created_at: datetime
    last_activity_at: datetime = Field(alias="updated_at")
    ip_address: str
