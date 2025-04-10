from sqlmodel import Field, Session, SQLModel, create_engine # type: ignore
from datetime import datetime, timedelta

f = open('db//password.txt', 'r')
password = f.readline()
password.strip()

engine = create_engine("postgresql://postgres:postgres@db:5432/checkpoint-db", echo=True)
SessionLocal = engine.connect()

class User(SQLModel, table=True):
    __tablename__ = "User"
    username: str = Field(primary_key=True, index=True, unique=True)
    email: str = Field(index=True, unique=True)
    full_name: str 
    user_id: str = Field(unique=True)
    hashed_password: str
    admin: bool = Field(default=False)

class Item(SQLModel, table=True):
    __tablename__ = "Item"
    id: str = Field(primary_key=True, index=True, unique=True) #this should ideally be a serial number (unique)
    name: str = Field(index=True)
    description: str = Field()
    model: str = Field()
    location: str | None = Field(default=None)
    availability: bool = Field() # available = true, ow = false
    borrow_period_days: timedelta
    status: str = Field() 

class Borrow(SQLModel, table=True):
    __tablename__ = "Borrow"
    class Config: arbitrary_types_allowed=True
    borrow_id: int = Field(primary_key=True)
    item_id: str = Field(index=True, foreign_key="Item.id")
    username: str = Field(index=True, foreign_key="User.username")
    date_borrowed: datetime = Field()
    date_returned: datetime | None = Field(default=None)
    date_due: datetime = Field()
    active: bool = Field()

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session


