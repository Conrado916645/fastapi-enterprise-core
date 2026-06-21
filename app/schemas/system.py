# app/schemas/system.py
from pydantic import BaseModel
from typing import List

class DashboardMetrics(BaseModel):
    total_users: int
    human_users: int
    service_accounts: int
    total_apps: int

class DashboardResponse(BaseModel):
    metrics: DashboardMetrics
    installed_apps: List[str]
    recent_logs: List[str]