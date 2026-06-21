# app/api/v1/system.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
import os
from datetime import datetime

from app.core.database import get_db
from app.api.dependencies import require_permission
from app.models.user import User
from app.schemas.system import DashboardResponse
from app.core.registry import APP_REGISTRY # 🚨 Import your Registry

router = APIRouter()

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