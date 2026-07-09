# app/api/v1/users.py
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, require_permission, get_base_user
from app.core.database import get_db
from app.core.rate_limit import limiter
from app.schemas.users import UserCreate, UserResponse, UserUpdate, AdminPasswordReset, UserProfileUpdate
from app.services import user_services

from app.core.logger import logger 

from app.schemas.users import UserChangePassword

from app.models.user import User

from app.core.registry import APP_REGISTRY

router = APIRouter()


@router.post("/me/change-password")
async def change_own_password(
    password_data: UserChangePassword, 
    current_user: User = Depends(get_base_user), 
    db: Session = Depends(get_db)
):
    success = user_services.change_user_password(db, current_user, password_data.old_password, password_data.new_password)
    
    if not success:
        logger.warning(f"Failed password change for '{current_user.username}': Incorrect old password.")
        raise HTTPException(status_code=400, detail="Incorrect current password")
        
    logger.info(f"User '{current_user.username}' successfully updated their password.")
    return {"message": "Password successfully updated. Full access granted."}


@router.patch("/me/profile")
async def update_own_profile(profile_data: UserProfileUpdate, current_user: User = Depends(get_base_user), db: Session = Depends(get_db)
):
    updated_user = user_services.update_user_profile(db, current_user, profile_data)
    logger.info(f"User '{current_user.username}' updated their profile information.")
    return current_user

@router.delete("/me")
async def delete_own_account(
    current_user: User = Depends(get_base_user), 
    db: Session = Depends(get_db)
):
    user_services.delete_own_account(db, current_user)
    logger.warning(f"User '{current_user.username}' has soft-deleted their own account.")
    return {"message": "Your account has been successfully soft-deleted."}