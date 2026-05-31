# app/api/dependencies.py
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
import jwt

from app.core.security import SECRET_KEY, ALGORITHM
from app.core.database import get_db
from app.models.user import User  

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_base_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Decodes the JWT and fetches the real user from the database."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type. Access token required.")
            
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
            
    except Exception:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
        

    user = db.query(User).filter(User.username == username).first()
    
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")
        
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")
        
    # We return the actual SQLAlchemy User object, not a dictionary!
    return user


async def get_current_user(user: User = Depends(get_base_user)):
    """Checks if the user is forced to reset their password."""
    
    if user.requires_password_change:
        raise HTTPException(
            status_code=403, 
            detail="PASSWORD_CHANGE_REQUIRED"
        )
        
    return user


def require_permission(module: str, action: str):
    """Checks if the user has specific module permissions."""
    
    # Notice this depends on get_current_user (Bouncer 2)
    def permission_checker(user: User = Depends(get_current_user)):
        
        # Because 'user' is a database object, we access permissions with dot notation
        user_permissions = user.permissions or {}
        module_permissions = user_permissions.get(module, [])

        if action not in module_permissions:
            raise HTTPException(
                status_code=403, 
                detail=f"Access denied: You need '{action}' permission for '{module}'."
            )
            
        return user
        
    return permission_checker