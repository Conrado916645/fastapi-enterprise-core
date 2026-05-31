from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
import jwt
from app.core.security import SECRET_KEY, ALGORITHM

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        

        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type. Access token required.")
            
        username: str = payload.get("sub")
        permissions: dict = payload.get("permissions") 
        
        if username is None or permissions is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
            
        return {"username": username, "permissions": permissions}
    except Exception:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

def require_permission(module: str, action: str):
    def permission_checker(current_user: dict = Depends(get_current_user)):
        user_permissions = current_user.get("permissions", {})
        
        module_permissions = user_permissions.get(module, [])

        if action not in module_permissions:
            raise HTTPException(
                status_code=403, 
                detail=f"Access denied: You need '{action}' permission for '{module}'."
            )
        return current_user
        
    return permission_checker