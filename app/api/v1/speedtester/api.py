from fastapi import APIRouter
from app.api.v1.speedtester.router import router as speedtester_user_router
api_router = APIRouter()

api_router.include_router(speedtester_user_router,  tags=["speedtester"] )
