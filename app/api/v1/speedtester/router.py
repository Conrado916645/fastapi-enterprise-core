# app/api/v1/speedtester/routes.py
from fastapi import APIRouter, Depends
from datetime import datetime
from app.schemas.speedtest import SpeedtestResponse
from app.api.dependencies import require_permission  

router = APIRouter()

fake_speedtest_db = [
    {
        "id": 1, 
        "download_mbps": 125.5, 
        "upload_mbps": 45.2, 
        "ping_ms": 12.0, 
        "timestamp": datetime.now()
    }
]

@router.get("/history", response_model=list[SpeedtestResponse], dependencies=[Depends(require_permission("speedtester", "read"))])
async def get_speedtest_history():
    return fake_speedtest_db

@router.post("/run", response_model=SpeedtestResponse, dependencies=[Depends(require_permission("speedtester", "create"))])
async def run_dummy_speedtest():
    
    import random
    
    new_test = {
        "id": len(fake_speedtest_db) + 1,
        "download_mbps": round(random.uniform(50.0, 300.0), 2),
        "upload_mbps": round(random.uniform(10.0, 100.0), 2),
        "ping_ms": round(random.uniform(5.0, 40.0), 2),
        "timestamp": datetime.now()
    }
    
    fake_speedtest_db.append(new_test)
    
    return new_test