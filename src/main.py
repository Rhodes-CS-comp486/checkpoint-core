from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status, Query
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlmodel import Session, select
import jwt 
from jwt.exceptions import InvalidTokenError
from src import database as db
from src.database import User, Item, engine
from pydantic import BaseModel


PUBLIC_KEY = "notused"
SECRET_KEY = "secretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

SessionDep = Annotated[Session, Depends(db.get_session)]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def lifespan(app: FastAPI):
    db.create_db_and_tables()
    with Session(engine) as session:
        seed_sample(session)
    yield
app = FastAPI(lifespan=lifespan)

async def get_user(username: str, session: SessionDep) -> User:
    user = session.get(User, username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def authenticate_user(db, username: str, password: str):
    user = await get_user(username, db)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], session: SessionDep):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = await get_user(token_data.username, session)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.admin:
        raise HTTPException(status_code=400, detail="Administrator user")
    return current_user


##### mock sample data for testing


def seed_sample(session):
    existing_users = session.exec(select(User)).all()
    if existing_users:
        return

    sample_users = [
        User(username="dzhanbyrshy", email="dz@example.com", full_name="Dimash Zhanbyrshy",
             hashed_password=get_password_hash("dz123"), admin=True),
        User(username="jhall", email="jh@example.com", full_name="Jules Hall",
             hashed_password=get_password_hash("jh123"), admin=False),
        User(username="egantulga", email="eg@example.com", full_name="EK Gantulga",
             hashed_password=get_password_hash("eg123"), admin=False)
    ]

    for user in sample_users:
        session.add(user)

    existing_items = session.exec(select(Item)).all()
    if existing_items:
        return  # Already seeded

    sample_items = [
        Item(name="Camera", description="DSLR camera", model="Canon EOS 90D",
            availability=True, status="available"),
        Item(name="Tripod", description="Adjustable tripod stand", model="Manfrotto Compact",
            availability=False, status="borrowed"),
        Item(name="Whiteboard", description="Magnetic whiteboard", model="Quartet",
            availability=True, status="available"),
        Item(name="Microscope", description="Science lab microscope", model="AmScope B120C",
            availability=False, status="reserved"),
    ]

    for item in sample_items:
        session.add(item)

    session.commit()

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep
) -> Token:
    user = await authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return Token(access_token=access_token, token_type="bearer")

@app.get("/users/me")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user

@app.get("/users/all")
async def list_users(session: SessionDep):
    return session.exec(select(User)).all()

@app.get("/")
def read_root():
    return {"Public_Key": PUBLIC_KEY}

@app.put("/users/")
async def new_user(user: User, session: SessionDep):
    db_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=get_password_hash(user.hashed_password),
        admin=user.admin,
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return {"Account Created.\nUser": db_user}

@app.put("/items/{item_id}")
def update_item(item_id: int, item: Item):
    return {"item_name": item.name, "item_id": item_id}

@app.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}

@app.get("/items/filter")
async def filter_items(
    session: SessionDep,
    availability: bool | None = Query(default=None),
    category: str | None = Query(default=None),
    status: str | None = Query(default=None)
):
    query = select(Item)

    if availability is not None:
        query = query.where(Item.availability == availability)
    if category:
        query = query.where(Item.model == category)
    if status:
        query = query.where(Item.status == status)
    results = session.exec(query).all()
    return results
