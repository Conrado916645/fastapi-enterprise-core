import uuid
from sqlalchemy import Boolean, Column, DateTime, Integer, String, JSON, func
from sqlalchemy.orm import relationship
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    # --- CORE IDENTIFICATION ---
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String, nullable=False)

    # --- PROFILE INFORMATION ---
    full_name = Column(String, nullable=True)
    phone_number = Column(String, nullable=True)
    date_of_birth = Column(DateTime(timezone=True), nullable=True)

    # --- PERMISSIONS & SECURITY ---
    permissions = Column(JSON, default={})
    is_active = Column(Boolean, default=True)
    is_deleted = Column(Boolean, default=False)
    is_service_account = Column(Boolean, default=False)
    api_key_hash = Column(String, nullable=True)
    
    # --- PASSWORD & LOCKOUT LOGIC ---
    requires_password_change = Column(Boolean, default=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)

    # --- AUDIT & TIMESTAMPS ---
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    status_changed_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(String, nullable=True) 

    # --- MFA RELATIONSHIP ---
    mfa_methods = relationship("UserMFAMethod", back_populates="user", cascade="all, delete-orphan")

    @property
    def is_totp_enabled(self) -> bool:
        """Returns True if the user has a verified TOTP method in the related table."""
        return any(
            method.method_type == "totp" and method.is_verified 
            for method in self.mfa_methods
        )