from sqlalchemy.orm import Session
from app.models.user import User
from app.schemas.users import UserCreate
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