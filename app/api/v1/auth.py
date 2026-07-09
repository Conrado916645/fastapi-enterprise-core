import pyotp
from fastapi import APIRouter, HTTPException, Request, Depends, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import jwt

from app.core.database import get_db
from app.models.user import User
from app.core.security import create_access_token, create_refresh_token, verify_password
from app.core.rate_limit import limiter
from app.core.config import settings
from app.core.logger import logger
from pydantic import BaseModel

from app.schemas.mfa_totp import MFAVerifyLoginSchema

router = APIRouter()


@router.post("/login")
@limiter.limit("5/minute")
async def login(
    request: Request, 
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
        
    if user.locked_until and user.locked_until > datetime.utcnow():
        logger.warning(f"Login blocked: Account locked for {user.username} until {user.locked_until}")
        raise HTTPException(status_code=403, detail="Account locked due to too many failed attempts. Try again later.")
    
    if not verify_password(form_data.password, user.hashed_password):
        user.failed_login_attempts += 1
        
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
            logger.critical(f"BRUTE FORCE DETECTED: User '{user.username}' locked out for 15 minutes.")
        
        db.commit()
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    if not user.is_active:
        logger.warning(f"Failed login attempt: Account disabled for user {user.username}")
        raise HTTPException(status_code=403, detail="Account has been deactivated. Contact an administrator.")

    if user.failed_login_attempts > 0:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()
        
    active_mfa_methods = [m for m in user.mfa_methods if m.is_verified]
    
    if len(active_mfa_methods) > 0:
        mfa_token_payload = {"sub": user.username, "type": "mfa_pending"}
        mfa_token = create_access_token(data=mfa_token_payload, expires_delta=timedelta(minutes=5))
        
        return {
            "status": "mfa_required",
            "mfa_token": mfa_token,
            "methods": [m.method_type for m in active_mfa_methods],
            "message": "Multi-Factor Authentication required."
        }
        
    user.last_login_at = datetime.utcnow()
    db.commit()
    
    token_payload = {"sub": user.username, "permissions": user.permissions}
    access_token = create_access_token(data=token_payload)
    refresh_token = create_refresh_token(data=token_payload)
    
    return {
        "access_token": access_token, 
        "refresh_token": refresh_token, 
        "token_type": "bearer"
    }


@router.post("/login/mfa-verify")
@limiter.limit("5/minute")
async def verify_login_mfa(
    request: Request,
    payload: MFAVerifyLoginSchema,
    db: Session = Depends(get_db)
):
    
    try:
        token_data = jwt.decode(payload.mfa_token, settings.SECRET_KEY, algorithms=["HS256"])
        
        if token_data.get("type") != "mfa_pending":
            raise HTTPException(status_code=401, detail="Invalid token type.")
            
        username = token_data.get("sub")
        user = db.query(User).filter(User.username == username).first()
        
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="Invalid session or deactivated user.")

        totp_method = next((m for m in user.mfa_methods if m.is_verified and m.method_type == "totp"), None)
        if not totp_method:
            raise HTTPException(status_code=400, detail="MFA method not found.")

        totp = pyotp.TOTP(totp_method.secret_configuration)
        if not totp.verify(payload.code):
            raise HTTPException(status_code=401, detail="Invalid authentication code.")

        user.last_login_at = datetime.utcnow()
        db.commit()

        token_payload = {"sub": user.username, "permissions": user.permissions}
        access_token = create_access_token(data=token_payload)
        refresh_token = create_refresh_token(data=token_payload)
        
        return {
            "access_token": access_token, 
            "refresh_token": refresh_token, 
            "token_type": "bearer"
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="MFA session expired. Please log in again.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid MFA session.")


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
        
        if not user.is_active:
            logger.warning(f"Refresh blocked: Account disabled for user {user.username}")
            # FIX: This raise was incorrectly indented outside the if statement in your original code
            raise HTTPException(status_code=403, detail="Account has been deactivated. Contact an administrator.")
    
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