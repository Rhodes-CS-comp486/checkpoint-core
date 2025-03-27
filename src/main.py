from typing import Annotated
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from src.database import SessionLocal
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from src.models import User as DBUser
from src.models import Item as DBItem
from src.database import Base, engine


Base.metadata.create_all(bind=engine)

db = engine.connect()
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "admin": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "admin": True,
    },
}
class UserCreate(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    password: str  # Add password field
    admin: bool | None = None

class Token(BaseModel):
    access_token: str
    token_type: str

class ItemSchema(BaseModel):
    name: str
    id: int

class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    admin: bool | None = None

class UserInDB(User):
    hashed_password: str

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}

def fake_hash_password(password: str):
    return "fakehashed" + password

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def fake_decode_token(token):
    user = get_user(fake_users_db, token)
    return user

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.admin:
        raise HTTPException(status_code=400, detail="Administrator user")
    return current_user

@app.get("/test-db")
def test_db_connection(db: Session = Depends(get_db)):
    result = db.execute(text("SELECT 1")).fetchone()
    if result:
        return {"message": "Database connection successful!"}
    else:
        return {"error": "No result returned from database"}


@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post("/users/")
async def create_user(user: User, password: str, db: Session = Depends(get_db)):
    db_user = DBUser(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=fake_hash_password(user.hashed_password),
        admin=user.admin or False,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"user": db_user}


@app.put("/items/{item_id}")
def update_item(item_id: int, item: DBItem):
    return {"item_name": item.name, "item_id": item_id}

@app.post("/items/borrow/{item_id}")
def borrow_item(
    item_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db)
):
    item = db.query(DBItem).filter(DBItem.id == item_id).first()

    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    if item.borrowed:
        raise HTTPException(status_code=400, detail="Item already borrowed")

    # Mark item as borrowed
    item.borrowed = True
    item.borrowed_by = current_user.username
    db.commit()
    db.refresh(item)

    return {"message": f"{current_user.username} successfully borrowed {item.name}"}
@app.get("/items/")
def read_available_items(db: Session = Depends(get_db)):
    items = db.query(DBItem).filter(DBItem.borrowed == False).all()
    return {"available_items": items}


@app.post("/add-items/")
async def add_item(
        item: ItemSchema,
        current_user: Annotated[User, Depends(get_current_user)],
        db: Session = Depends(get_db)
):
    # Ensure the user is an admin
    if not current_user.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to perform this action"
        )

    # Create a new item in the database
    db_item = DBItem(
        id=item.id,
        name=item.name
    )
    db.add(db_item)
    db.commit()
    db.refresh(db_item)

    return {"message": f"Item '{item.name}' added successfully", "item": db_item}


