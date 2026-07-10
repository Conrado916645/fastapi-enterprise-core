# app/api/v1/system.py
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
import os
from datetime import datetime

from app.core.database import get_db
from app.api.dependencies import get_base_user, get_current_user,require_permission
from app.models.user import User
from app.schemas.system import DashboardResponse
from app.core.registry import APP_REGISTRY
from app.schemas.users import AdminPasswordReset, UserCreate, UserResponse, UserUpdate
from app.services import system 
from app.core.rate_limit import limiter
from app.core.logger import logger

router = APIRouter()

@router.delete("/users/{user_id}", dependencies=[Depends(require_permission("system", "delete"))])
async def delete_user(
    user_id: str, 
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_base_user) 
):
    user_to_delete = system.soft_delete_user(db, user_id=user_id)
    
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")
        
    logger.warning(
        f"USER DELETED: User '{user_to_delete.username}' (ID: {user_id}) "
        f"was deleted by Admin '{current_admin.username}'."
    )
        
    return {"message": "User account successfully soft-deleted."}

@router.patch("/users/{user_id}/restore", dependencies=[Depends(require_permission("system", "update"))])
async def restore_user(
    user_id: str, 
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_base_user) 
):
    restored_user = system.restore_soft_deleted_user(db, user_id=user_id)
    
    if not restored_user:
        raise HTTPException(status_code=404, detail="User not found or not deleted")
        
    logger.info(
        f"USER RESTORED: User '{restored_user.username}' (ID: {user_id}) "
        f"was restored by Admin '{current_admin.username}'."
    )
        
    return {"message": "User account successfully restored."}

@router.post("/users/{user_id}/unlock", dependencies=[Depends(require_permission("system", "update"))])
async def admin_unlock_user(user_id: str, db: Session = Depends(get_db)):
    success = system.unlock_user_account(db, user_id=user_id)
    
    if not success:
        logger.warning(f"Account unlock failed: User ID '{user_id}' does not exist.")
        raise HTTPException(status_code=404, detail="User not found")
    
    logger.info(f"ADMIN ACTION: Account manually unlocked for user ID '{user_id}'")
    return {"message": "User account successfully unlocked."}

@router.post("/users/{user_id}/generate-api-key", dependencies=[Depends(require_permission("system", "update"))])
async def create_api_key(user_id: str, db: Session = Depends(get_db)):
    raw_key = system.generate_service_account_key(db, user_id=user_id)
    
    if not raw_key:
        raise HTTPException(status_code=404, detail="User not found")
        
    return {
        "message": "API Key generated successfully. Save this now, you will never see it again.",
        "api_key": raw_key
    }

@router.post("/users/{user_id}/reset-password", dependencies=[Depends(require_permission("system", "update"))])
async def admin_reset_password(user_id: str, password_data: AdminPasswordReset, db: Session = Depends(get_db)):
    updated_user = system.reset_user_password(db, user_id=user_id, new_password=password_data.new_password)
    
    if not updated_user:
        logger.warning(f"Password reset failed: User ID '{user_id}' does not exist.")
        raise HTTPException(status_code=404, detail="User not found")
    
    logger.warning(f"ADMIN OVERRIDE: Password forcefully reset for user ID '{user_id}'")
    return {"message": "User password successfully reset."}

@router.patch("/users/{user_id}", response_model=UserResponse, dependencies=[Depends(require_permission("system", "update"))])
async def update_user(user_id: str, user_in: UserUpdate, db: Session = Depends(get_db)):
    updated_user = system.update_user(db, user_id=user_id, user_in=user_in)
    
    if not updated_user:
        logger.warning(f"User update failed: ID '{user_id}' does not exist.")
        raise HTTPException(status_code=404, detail="User not found")

    logger.info(f"Security Alert: User ID '{user_id}' was updated. Active Status: {updated_user.is_active}")
    return updated_user


@router.get("/users", response_model=list[UserResponse], dependencies=[Depends(require_permission("system", "read"))])
async def get_all_users(request: Request, db: Session = Depends(get_db)):
    users = system.get_all_users(db)
    logger.info(f"User directory accessed. Returned {len(users)} user records.")
    return users

@router.get("/users/{user_id}", response_model=UserResponse, dependencies=[Depends(require_permission("system", "read"))])
async def get_user_by_id(request: Request, user_id: str, db: Session = Depends(get_db)):
    user = system.get_user_by_id(db, user_id=user_id)
    
    if not user:
        logger.warning(f"User lookup failed: ID '{user_id}' not found.")
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("/register", response_model=UserResponse,dependencies=[Depends(require_permission("system", "create"))])
@limiter.limit("3/minute")
async def register_user(request: Request, user_in: UserCreate, db: Session = Depends(get_db)):
    existing_user = system.get_user_by_username(db, username=user_in.username)
    
    if existing_user:
        logger.warning(f"Registration failed: Username '{user_in.username}' is already taken.")
        raise HTTPException(status_code=400, detail="Username already registered")
    
    new_user = system.create_user(db, user_in=user_in)
    
    logger.info(f"Account Created: New user '{new_user.username}' registered. ID: {new_user.id}")
    return new_user


@router.get("/dashboard", response_model=DashboardResponse, dependencies=[Depends(require_permission("system", "read"))])
async def get_dashboard_metrics(db: Session = Depends(get_db)):
    
    # 1. Database metrics
    active_users = db.query(User).filter(User.is_deleted == False)
    total_users = active_users.count()
    service_accounts = active_users.filter(User.is_service_account == True).count()
    human_users = active_users.filter(User.is_service_account == False).count()

    # 2. 🚨 DYNAMIC APP LIST
    # Automatically extracts keys from your registry (e.g., ['users', 'speedtester', 'system'])
    installed_apps = list(APP_REGISTRY.keys())

    # 3. Log reading logic
    today_str = datetime.now().strftime("%Y-%m-%d")
    log_file_path = f"logs/api_{today_str}.log"
    recent_logs = []
    
    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as file:
            lines = file.readlines()
            recent_logs = [line.strip() for line in lines[-20:]]
            recent_logs.reverse() 
    else:
        recent_logs = ["No logs recorded yet for today."]

    return {
        "metrics": {
            "total_users": total_users,
            "human_users": human_users,
            "service_accounts": service_accounts,
            "total_apps": len(installed_apps)
        },
        "installed_apps": installed_apps,
        "recent_logs": recent_logs
    }

@router.get("/installed-apps", dependencies=[Depends(get_current_user)])
async def get_installed_apps():
    """The frontend calls this to dynamically draw the permission checkboxes."""
    return {"installed_apps": APP_REGISTRY}
