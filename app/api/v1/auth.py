from fastapi import APIRouter, HTTPException, Request, Depends, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User
from app.core.security import create_access_token, create_refresh_token, verify_password
from app.core.rate_limit import limiter
import jwt
from app.core.config import settings

from app.core.logger import logger

router = APIRouter()

@router.post("/login")
@limiter.limit("5/minute")
async def login(
    request: Request, 
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    token_payload = {"sub": user.username, "permissions": user.permissions}
    access_token = create_access_token(data=token_payload)
    refresh_token = create_refresh_token(data=token_payload)
    
    return {
        "access_token": access_token, 
        "refresh_token": refresh_token, 
        "token_type": "bearer"
    }

@router.post("/refresh")
@limiter.limit("5/minute")
async def refresh_access_token(
    request: Request, 
    refresh_token: str = Body(..., embed=True), 
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=["HS256"])
        
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
            
        username: str = payload.get("sub")
        
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="User no longer exists")
            
        new_access_token = create_access_token(
            data={"sub": user.username, "permissions": user.permissions}
        )
        
        return {"access_token": new_access_token, "token_type": "bearer"}
    
    except jwt.ExpiredSignatureError:
        logger.warning("A user attempted to refresh using an EXPIRED token.")
        raise HTTPException(status_code=401, detail="Token expired")
        
    except jwt.PyJWTError as e:
        logger.error(f"Invalid JWT Signature detected: {str(e)}") 
        raise HTTPException(status_code=401, detail="Invalid token signature")
        
    except Exception as e:
        logger.critical(f"CRITICAL SYSTEM ERROR in /refresh: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")