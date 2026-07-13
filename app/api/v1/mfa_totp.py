import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, logger
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.database import get_db
from app.core.security import verify_password
from app.models.user import User
from app.models.mfa import UserMFAMethod
from app.schemas.mfa_totp import DisableMFASchema, VerifyMFASchema
from app.api.dependencies import get_base_user, get_current_user, require_permission
from app.core.rate_limit import limiter
from app.core.logger import logger

# 1. ADDED missing import for disable_mfa service
from app.services.mfa_totp import setup_totp, verify_totp, disable_mfa 

router = APIRouter()

# 2. RENAMED endpoint to avoid shadowing 'setup_totp'
@router.get("/setup/totp")
async def setup_totp_route(
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):  
    # Assuming your service functions are synchronous. 
    # If they are async, you must add 'await' here!
    secret = setup_totp(db, current_user) 
    logger.info(f"User '{current_user.username}' initiated TOTP setup. Secret generated.")
    return {"secret": secret}


# 3. RENAMED endpoint to avoid shadowing 'verify_totp'
@router.post("/verify/totp")
async def verify_totp_route(
    payload: VerifyMFASchema, 
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    verification_result = verify_totp(db, current_user, payload.code)
    if not verification_result:
        logger.warning(f"User '{current_user.username}' failed TOTP verification with token: {payload.token}")
        raise HTTPException(status_code=400, detail="Invalid verification code.")
    logger.info(f"User '{current_user.username}' successfully verified TOTP setup.")
    return {"message": "Authenticator App successfully linked!"}


# 4. RENAMED endpoint to avoid shadowing 'disable_mfa'
@router.post("/disable")
@limiter.limit("5/minute")
async def disable_mfa_route(
    request: Request,
    payload: DisableMFASchema,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    disable_mfa(db, current_user)
    logger.info(f"MFA successfully disabled for user {current_user.username}")
    return {"message": "Two-Factor Authentication has been completely disabled."}