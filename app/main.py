from fastapi import FastAPI,Request
import time
from app.api.v1.api import api_router as main_api_auth_v1
from app.api.v1.system import router as system_router
from slowapi.errors import RateLimitExceeded
from app.core.rate_limit import limiter, _rate_limit_exceeded_handler

from fastapi.middleware.cors import CORSMiddleware

from app.core.database import engine
from app.models import user

# ---- INITIALIZATION CODE ---
from contextlib import asynccontextmanager
from app.core.database import engine, SessionLocal
from app.core.init_db import create_super_admin
# ----------------------------

from app.core.config import settings

# API ENDPOINTS
from app.api.v1.speedtester.api import api_router as speedtester_api_router_v1

# CENRALIZED LOGGING
from app.core.logger import logger



user.Base.metadata.create_all(bind=engine)

# --- Define the Lifespan (Startup/Shutdown events) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    db = SessionLocal()
    try:
        create_super_admin(db)
    finally:
        db.close()
        
    yield

app = FastAPI(
    title="Philippine Navy API",
    description="API for managing Philippine Navy applications.",
    version="1.0.0",
    lifespan=lifespan,

    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT == "development" else None,
    openapi_url="/openapi.json" if settings.ENVIRONMENT == "development" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.DOMAIN],
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"], 
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# API ENDPOINTS
app.include_router(speedtester_api_router_v1, prefix="/api/v1/speedtester")
app.include_router(main_api_auth_v1, prefix="/api/v1")
app.include_router(system_router, prefix="/api/v1/system", tags=["System Admin"])

@app.get("/",  tags=["System"])
async def root():
    return {"message": "Welcome to your personal API!"}


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # 1. Extract the IP Address (Fallback to "Unknown" if it's missing)
    client_ip = request.client.host if request.client else "Unknown IP"
    
    # 2. Extract the Browser/Device info (User-Agent)
    user_agent = request.headers.get("user-agent", "Unknown Device")
    
    # Process the actual API request
    response = await call_next(request)
    
    process_time = (time.time() - start_time) * 1000
    
    # 3. Log everything together in a lean format!
    logger.info(
        f"IP: {client_ip} | {request.method} {request.url.path} - Status: {response.status_code} - {process_time:.2f}ms | Agent: {user_agent}"
    )
    
    return response