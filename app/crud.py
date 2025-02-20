from sqlalchemy.orm import Session
import models
import schemas
from app.main import get_password_hash


# User CRUD operations
def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def create_user(db: Session, user: schemas.UserCreate):
    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=get_password_hash(user.password)
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Equipment CRUD operations
def get_equipment(db: Session, skip: int = 0, limit: int = 10):
    return db.query(models.Equipment).offset(skip).limit(limit).all()

def create_equipment(db: Session, equipment: schemas.EquipmentCreate):
    db_equipment = models.Equipment(name=equipment.name, description=equipment.description)
    db.add(db_equipment)
    db.commit()
    db.refresh(db_equipment)
    return db_equipment
