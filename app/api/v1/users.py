from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, require_permission
from app.core.database import get_db
from app.core.rate_limit import limiter
from app.schemas.users import UserCreate, UserResponse 
from app.services import user_services

router = APIRouter()


@router.post("/register", response_model=UserResponse)
@limiter.limit("3/minute")
async def register_user(request: Request, user_in: UserCreate, db: Session = Depends(get_db)):
    
    existing_user = user_services.get_user_by_username(db, username=user_in.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    new_user = user_services.create_user(db, user_in=user_in)

    return new_user

@router.get("/", dependencies=[Depends(get_current_user)])
@limiter.limit("3/minute")
async def get_all_users(request: Request, db: Session = Depends(get_db)):
    users = user_services.get_all_users(db)
    return users

@router.get("/{user_id}", dependencies=[Depends(get_current_user)])
@limiter.limit("3/minute")
async def get_user_by_id(request: Request, user_id: int, db: Session = Depends(get_db)):
    user = user_services.get_user_by_id(db, user_id=user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user