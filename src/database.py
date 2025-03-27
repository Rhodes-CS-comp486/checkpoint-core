from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Define the path to your database file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = "sqlite:///./db/database.db"

# Create the engine to interact with the database
# `check_same_thread=False` is required for SQLite to allow multiple threads
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Create a session factory for database sessions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Define the base class for all ORM models
Base = declarative_base()