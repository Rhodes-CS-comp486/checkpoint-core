from datetime import timedelta
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session
import jwt
from src import database as db, security as sec
from src.database import User

engine = db.create_engine("postgresql+psycopg2://postgres:postgres@db:5432/DB", echo=True)
db = engine.connect()
users = "Users"

SessionDep = Annotated[Session, Depends(db.get_session)]

app = FastAPI()

@app.lifespan("startup")
def on_startup():
    db.create_db_and_tables()

async def get_user(username: str, session: SessionDep) -> User:
    user = session.get(User, username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

async def get_current_user(token: Annotated[str, Depends(sec.oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, sec.SECRET_KEY, algorithms=[sec.ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = sec.TokenData(username=username)
    except sec.InvalidTokenError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.admin:
        raise HTTPException(status_code=400, detail="Administrator user")
    return current_user

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = sec.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = sec.create_access_token(data={"sub": user.username})
    return Token(access_token=access_token, token_type="bearer")

@app.get("/users/me")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user

@app.get("/")
def read_root():
    return {"Public_Key": sec.PUBLIC_KEY}

@app.put("/users/")
async def new_user(user: User, session: SessionDep):
    db_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=(user.hashed_password),
        admin=user.admin,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return {"Account Created.\nUser": db_user}

@app.put("/items/{item_id}")
def update_item(item_id: int, item: Item):
    return {"item_name": item.name, "item_id": item_id}

@app.get("/items/")
async def read_items(token: Annotated[str, Depends(sec.oauth2_scheme)]):
    return {"token": token}
