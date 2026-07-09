from sqlalchemy import Column, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.core.database import Base

class UserMFAMethod(Base):
    __tablename__ = "user_mfa_methods"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    method_type = Column(String, nullable=False) 
    
    secret_configuration = Column(String, nullable=False) 
    
    is_verified = Column(Boolean, default=False)
    
    is_primary = Column(Boolean, default=False) 
    
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="mfa_methods")