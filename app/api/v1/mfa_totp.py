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

router = APIRouter()

@router.get("/mfa/setup/totp")
async def setup_totp(
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """Generates a new TOTP secret and returns the text string."""
    
    mfa_record = db.query(UserMFAMethod).filter(
        UserMFAMethod.user_id == current_user.id,
        UserMFAMethod.method_type == "totp",
        UserMFAMethod.is_verified == False
    ).first()

    secret = pyotp.random_base32()

    if not mfa_record:
        mfa_record = UserMFAMethod(
            user_id=current_user.id,
            method_type="totp",
            secret_configuration=secret,
            is_primary=True 
        )
        db.add(mfa_record)
    else:
        mfa_record.secret_configuration = secret

    db.commit()

    return {"secret": secret}


@router.post("/mfa/verify/totp")
async def verify_totp(
    payload: VerifyMFASchema, 
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """Verifies the 6-digit code and locks in the MFA configuration."""
    
    mfa_record = db.query(UserMFAMethod).filter(
        UserMFAMethod.user_id == current_user.id,
        UserMFAMethod.method_type == "totp",
        UserMFAMethod.is_verified == False
    ).first()

    if not mfa_record:
        raise HTTPException(status_code=400, detail="No pending MFA setup found.")

    totp = pyotp.TOTP(mfa_record.secret_configuration)
    if not totp.verify(payload.code):
        raise HTTPException(status_code=400, detail="Invalid verification code.")

    mfa_record.is_verified = True
    db.commit()
    
    return {"message": "Authenticator App successfully linked!"}

@router.post("/mfa/disable")
@limiter.limit("5/minute")
async def disable_mfa(
    request: Request,
    payload: DisableMFASchema,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Securely disables MFA by requiring a password re-verification."""
    
    # 1. Step-Up Authentication (Sudo Mode)
    if not verify_password(payload.password, current_user.hashed_password):
        # Log this! Someone might be poking around an unlocked machine.
        logger.warning(f"Failed MFA disable attempt for {current_user.username}: Incorrect password.")
        raise HTTPException(status_code=401, detail="Incorrect password. Cannot disable MFA.")

    # 2. Find all MFA methods attached to the user
    mfa_methods = db.query(UserMFAMethod).filter(UserMFAMethod.user_id == current_user.id).all()
    
    if not mfa_methods:
        raise HTTPException(status_code=400, detail="MFA is not enabled on this account.")

    # 3. Wipe the configurations
    for method in mfa_methods:
        db.delete(method)
        
    db.commit()

    logger.info(f"MFA successfully disabled for user {current_user.username}")
    return {"message": "Two-Factor Authentication has been completely disabled."}