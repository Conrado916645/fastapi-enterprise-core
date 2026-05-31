from sqlalchemy.orm import Session
from app.models.user import User
from app.core.security import get_password_hash
from app.core.config import settings
from app.core.logger import logger

def create_super_admin(db: Session):
    admin_username = settings.SUPER_ADMIN_USERNAME
    existing_admin = db.query(User).filter(User.username == admin_username).first()
    
    if not existing_admin:
        logger.info(f"Initialization: No Super Admin found. Bootstrapping initial system account: '{admin_username}'...")
        
        hashed_password = get_password_hash(settings.SUPER_ADMIN_PASSWORD)
        
        super_permissions = {
            "speedtester": ["create", "read", "update", "delete"],
            "users": ["create", "read", "update", "delete"]
        }
        
        new_admin = User(
            username=admin_username,
            hashed_password=hashed_password,
            permissions=super_permissions,
            is_active=True,
            requires_password_change=False
        )
        
        db.add(new_admin)
        db.commit()
        db.refresh(new_admin)

        logger.info(f"System Core Secured: Super Admin account '{admin_username}' created successfully. ID: {new_admin.id}")
    else:
        logger.debug("System bootstrap check: Super Admin already exists.")