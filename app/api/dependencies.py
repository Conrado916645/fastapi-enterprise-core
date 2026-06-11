# app/api/dependencies.py
from fastapi import Depends, HTTPException,Security
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.orm import Session
import jwt
import hashlib

from app.core.security import SECRET_KEY, ALGORITHM
from app.core.database import get_db
from app.models.user import User  

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_base_user(
    token: str = Depends(oauth2_scheme), 
    api_key: str = Security(api_key_header),
    db: Session = Depends(get_db)
):
    if not token and not api_key:
        raise HTTPException(status_code=401, detail="Authentication required. Provide a Bearer Token or X-API-Key.")

    user = None

    # 🤖 PATH A: MACHINE LOGIN (API Key)
    if api_key:
        # Hash the key they sent to compare it with the DB
        hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
        user = db.query(User).filter(User.api_key_hash == hashed_key).first()
        
        if not user:
            raise HTTPException(status_code=401, detail="Invalid API Key")

    # 👤 PATH B: HUMAN LOGIN (JWT Token)
    elif token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("type") != "access":
                raise HTTPException(status_code=401, detail="Invalid token type.")
            username: str = payload.get("sub")
        except Exception:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
            
        user = db.query(User).filter(User.username == username).first()

    # --- COMMON SECURITY CHECKS FOR BOTH ---
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")
        
    if user.is_deleted:
        raise HTTPException(
            status_code=403, 
            detail="Account has been permanently deactivated."
        )
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")
        
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