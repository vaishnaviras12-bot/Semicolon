"""
Pydantic Schemas for Authentication & User Account Management
=============================================================
Defines validation models for registration, login, token output, and user profile responses.
"""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_serializer

def serialize_utc_datetime(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class UserRegister(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    email: str
    created_at: datetime

    @field_serializer('created_at', mode='plain')
    def serialize_dates(self, dt: Optional[datetime], _info) -> Optional[str]:
        return serialize_utc_datetime(dt)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str = Field(..., pattern=r"^\d{6}$")  # exactly 6 digits
    new_password: str = Field(..., min_length=6, max_length=128)

class MessageResponse(BaseModel):
    message: str

