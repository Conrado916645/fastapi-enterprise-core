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

@router.post("/register", response_model=UserResponse)
@limiter.limit("3/minute")
async def register_user(request: Request, user_in: UserCreate, db: Session = Depends(get_db)):
    existing_user = user_services.get_user_by_username(db, username=user_in.username)
    
    if existing_user:
        logger.warning(f"Registration failed: Username '{user_in.username}' is already taken.")
        raise HTTPException(status_code=400, detail="Username already registered")
    
    new_user = user_services.create_user(db, user_in=user_in)
    
    logger.info(f"Account Created: New user '{new_user.username}' registered. ID: {new_user.id}")
    return new_user


@router.get("/", response_model=list[UserResponse], dependencies=[Depends(get_current_user)])
@limiter.limit("3/minute")
async def get_all_users(request: Request, db: Session = Depends(get_db)):
    users = user_services.get_all_users(db)

    logger.info(f"User directory accessed. Returned {len(users)} user records.")
    return users

@router.get("/{user_id}", response_model=UserResponse, dependencies=[Depends(get_current_user)])
@limiter.limit("3/minute")
async def get_user_by_id(request: Request, user_id: str, db: Session = Depends(get_db)):
    user = user_services.get_user_by_id(db, user_id=user_id)
    
    if not user:
        logger.warning(f"User lookup failed: ID '{user_id}' not found.")
        raise HTTPException(status_code=404, detail="User not found")
        
    return user

@router.patch("/{user_id}", response_model=UserResponse, dependencies=[Depends(require_permission("users", "update"))])
async def update_user(user_id: str, user_in: UserUpdate, db: Session = Depends(get_db)):
    updated_user = user_services.update_user(db, user_id=user_id, user_in=user_in)
    
    if not updated_user:
        logger.warning(f"User update failed: ID '{user_id}' does not exist.")
        raise HTTPException(status_code=404, detail="User not found")

    logger.info(f"Security Alert: User ID '{user_id}' was updated. Active Status: {updated_user.is_active}")
    return updated_user

@router.post("/{user_id}/reset-password", dependencies=[Depends(require_permission("users", "update"))])
async def admin_reset_password(user_id: str, password_data: AdminPasswordReset, db: Session = Depends(get_db)):
    updated_user = user_services.reset_user_password(db, user_id=user_id, new_password=password_data.new_password)
    
    if not updated_user:
        logger.warning(f"Password reset failed: User ID '{user_id}' does not exist.")
        raise HTTPException(status_code=404, detail="User not found")
    
    logger.warning(f"ADMIN OVERRIDE: Password forcefully reset for user ID '{user_id}'")
    return {"message": "User password successfully reset."}

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
    
    if not success:
        logger.warning(f"Failed personal password change for '{current_user.username}': Incorrect old password.")
        raise HTTPException(status_code=400, detail="Incorrect current password")
        
    logger.info(f"User '{current_user.username}' successfully updated their password and unlocked their account.")
    return {"message": "Password successfully updated. Full access granted."}

@router.post("/{user_id}/unlock", dependencies=[Depends(require_permission("users", "update"))])
async def admin_unlock_user(user_id: str, db: Session = Depends(get_db)):
    success = user_services.unlock_user_account(db, user_id=user_id)
    
    if not success:
        logger.warning(f"Account unlock failed: User ID '{user_id}' does not exist.")
        raise HTTPException(status_code=404, detail="User not found")
    
    logger.info(f"ADMIN ACTION: Account manually unlocked for user ID '{user_id}'")
    return {"message": "User account successfully unlocked."}

@router.post("/{user_id}/generate-api-key", dependencies=[Depends(require_permission("users", "update"))])
async def create_api_key(user_id: str, db: Session = Depends(get_db)):
    raw_key = user_services.generate_service_account_key(db, user_id=user_id)
    
    if not raw_key:
        raise HTTPException(status_code=404, detail="User not found")
        
    return {
        "message": "API Key generated successfully. Save this now, you will never see it again.",
        "api_key": raw_key
    }

@router.get("/system/installed-apps", dependencies=[Depends(get_current_user)])
async def get_installed_apps():
    """The frontend calls this to dynamically draw the permission checkboxes."""
    return {"installed_apps": APP_REGISTRY}

@router.patch("/me/profile")
async def update_own_profile(profile_data: UserProfileUpdate, current_user: User = Depends(get_base_user), db: Session = Depends(get_db)
):
    if profile_data.email:
        current_user.email = profile_data.email
    if profile_data.full_name:
        current_user.full_name = profile_data.full_name
        
    db.commit()
    db.refresh(current_user)
    
    logger.info(f"User '{current_user.username}' updated their personal profile.")
    
    return current_user

@router.delete("/{user_id}", dependencies=[Depends(require_permission("users", "delete"))])
async def delete_user(
    user_id: str, 
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_base_user) 
):
    user_to_delete = user_services.soft_delete_user(db, user_id=user_id)
    
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")
        
    logger.warning(
        f"USER DELETED: User '{user_to_delete.username}' (ID: {user_id}) "
        f"was deleted by Admin '{current_admin.username}'."
    )
        
    return {"message": "User account successfully soft-deleted."}