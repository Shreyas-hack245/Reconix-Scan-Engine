"""Pydantic schemas for user registration, authentication, and profile data."""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.models.user import UserRole


class UserCreate(BaseModel):
    """Payload for registering a new user."""

    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(default="", max_length=255)
    role: UserRole = UserRole.ANALYST


class UserLogin(BaseModel):
    """Payload for logging in via JSON (in addition to OAuth2 form login)."""

    email: EmailStr
    password: str


class UserRead(BaseModel):
    """User data returned by the API (never includes the password hash)."""

    id: str
    email: EmailStr
    full_name: str
    role: UserRole
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class Token(BaseModel):
    """JWT access token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class TokenData(BaseModel):
    """Decoded token claims (internal use)."""

    user_id: str
    role: str