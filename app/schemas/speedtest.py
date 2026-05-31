from pydantic import BaseModel
from datetime import datetime

class SpeedtestResponse(BaseModel):
    id: int
    download_mbps: float
    upload_mbps: float
    ping_ms: float
    timestamp: datetime

    class Config:
        from_attributes = True