from pydantic import BaseModel, field_validator,model_validator
import re
from typing import Dict, List, Optional
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    password: str
    confirm_password: str
    permissions: Optional[Dict[str, List[str]]] = {}

    @field_validator('password')
    @classmethod
    def validate_password_complexity(cls, v: str):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r"[A-Z]", v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r"[a-z]", v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r"\d", v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError('Password must contain at least one special character (!@#$%^&*)')
        return v
    
    @model_validator(mode='after')
    def verify_passwords_match(self) -> 'UserCreate':
        if self.password != self.confirm_password:
            raise ValueError('Passwords do not match')
        return self

class UserResponse(BaseModel):
    id: str
    username: str
    permissions: dict
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime] = None
    status_changed_at: Optional[datetime] = None
    requires_password_change: bool
    failed_login_attempts: int
    locked_until: Optional[datetime] = None
    class Config:
        from_attributes = True

class UserUpdate(BaseModel):
    permissions: Optional[dict] = None
    is_active: Optional[bool] = None

class AdminPasswordReset(BaseModel):
    new_password: str

class UserChangePassword(BaseModel):
    old_password: str
    new_password: str

class UserProfileUpdate(BaseModel):
    email: str | None = None
    full_name: str | None = None