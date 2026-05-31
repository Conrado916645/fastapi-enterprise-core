from sqlalchemy.orm import Session
from datetime import datetime
from app.models.user import User
from app.schemas.users import UserCreate, UserUpdate
from app.core.security import get_password_hash

def get_user_by_username(db: Session, username: str):
    """Fetches a user from the database by their username."""
    return db.query(User).filter(User.username == username).first()

def get_all_users(db: Session):
    """Fetches all users from the database."""
    return db.query(User).all()

def get_user_by_id(db: Session, user_id: int):
    """Fetches a user from the database by their ID."""
    return db.query(User).filter(User.id == user_id).first()

def create_user(db: Session, user_in: UserCreate):
    """Hashes the password and saves a new user to the database."""
    hashed_pwd = get_password_hash(user_in.password)
    
    new_user = User(
        username=user_in.username,
        hashed_password=hashed_pwd,
        permissions=user_in.permissions
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user

def update_user(db: Session, user_id: str, user_in: UserUpdate):
    """Updates a user's permissions or active status."""
    user = get_user_by_id(db, user_id)
    if not user:
        return None

    if user_in.is_active is not None and user.is_active != user_in.is_active:
        user.is_active = user_in.is_active
        user.status_changed_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    return user

def reset_user_password(db: Session, user_id: str, new_password: str):
    """Allows an Admin to forcefully overwrite a user's password."""
    user = get_user_by_id(db, user_id)
    if not user:
        return None
    
    user.hashed_password = get_password_hash(new_password)
    db.commit()
    return user