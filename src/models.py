from sqlalchemy import Column, Integer, String, Boolean
from src.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, nullable=True)
    hashed_password = Column(String)
    admin = Column(Boolean, default=False)

class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    borrowed = Column(Boolean, default=False)
    borrowed_by = Column(String, nullable=True)