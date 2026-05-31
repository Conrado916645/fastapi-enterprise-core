from sqlalchemy.orm import Session
from app.models.user import User
from app.core.security import get_password_hash
from app.core.config import settings

def create_super_admin(db: Session):
    admin_username = settings.SUPER_ADMIN_USERNAME
    
    existing_admin = db.query(User).filter(User.username == admin_username).first()
    
    if not existing_admin:
        print("No Super Admin found. Creating one now...")
        
        hashed_password = get_password_hash(settings.SUPER_ADMIN_PASSWORD)
        
        super_admin = User(
            username=admin_username,
            hashed_password=hashed_password,
            permissions={
                "speedtester": ["create", "read", "update", "delete"],
            }
        )
        
        db.add(super_admin)
        db.commit()
        print("Super Admin created successfully!")
    else:
        print("Super Admin already exists. Skipping creation.")