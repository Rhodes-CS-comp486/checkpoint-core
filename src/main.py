from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status, Query #type: ignore
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer #type: ignore
from passlib.context import CryptContext #type: ignore
from sqlmodel import Session, select #type: ignore
import jwt  #type: ignore
from jwt.exceptions import InvalidTokenError #type: ignore
from src import database as db
from src.database import User, Item, Borrow, engine#, seed_sample
from pydantic import BaseModel, EmailStr #type: ignore
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig

SECRET_KEY = "secretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class EmailSchema(BaseModel):
    email: list[EmailStr]
    subject: str
    body: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: str

class TokenData(BaseModel):
    username: str | None = None

SessionDep = Annotated[Session, Depends(db.get_session)]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

conf = ConnectionConfig(
    MAIL_USERNAME="checkpoint.notify@gmail.com",
    MAIL_PASSWORD="nxtz mfnx zdzi vayc",
    MAIL_FROM="checkpoint.notify@gmail.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_FROM_NAME="CheckPoint Notifier",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS = False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)

async def lifespan(app: FastAPI):
    db.create_db_and_tables()
    with Session(engine) as session:
        seed_sample(session)
    yield
app = FastAPI(lifespan=lifespan)

async def get_user(username: str, session: SessionDep) -> User: # type: ignore
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

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], session: SessionDep): # type: ignore
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
    return current_user

async def verify_admin(user: User): #type: ignore
    if user.admin == True:
        return True
    if user.admin == False:
        raise HTTPException(status_code=403, detail="This action requires elevated permissions. Ask an Administrator for help.")
    
async def check_item(item_id: str,
        session: SessionDep): #type: ignore
    item = session.get(Item, item_id)
    if item:
        return item
    elif item == None:
        raise HTTPException(status_code=404, detail="Item not found. Check Item ID and try again")

async def send_borrow_email(recipient: EmailStr, item_name: str, due_date: datetime):
    message = MessageSchema(
        subject="Item Borrowed Confirmation",
        recipients=[recipient],
        body=f"""Hello,

        You have successfully borrowed the item: {item_name}.

        📅 Due Date: {due_date.strftime('%Y-%m-%d %H:%M:%S')}

        Please make sure to return the item by the due date to avoid issues.

        Thank you,
        Checkpoint Equipment Services
        """,
        subtype="plain"
    )
    fm = FastMail(conf)
    await fm.send_message(message)

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep # type: ignore
) -> Token:
    user = await authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return Token(access_token=access_token, token_type="bearer", user_id=user.user_id)

@app.get("/users/me")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user

@app.get("/users/all")
async def list_users(session: SessionDep, # type: ignore
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    if await verify_admin(current_user):
        return session.exec(select(User)).all()

@app.get("/")
def read_root():
    return {"checkpoint-core"} 

@app.put("/users/")
async def new_user(user: User, session: SessionDep): # type: ignore
    if (get_user == user.username):
        raise HTTPException(status_code=403, detail="This username is in use. Please try another.")
    db_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        user_id=user.user_id,
        hashed_password=get_password_hash(user.hashed_password),
        admin=user.admin,
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return {"Account Created.": db_user}

@app.put("/users/{username}/elevate")
async def elevate_user(username: str, 
                       current_user: Annotated[User, Depends(get_current_active_user)], 
                       session: SessionDep): #type:ignore
    if await verify_admin(current_user):
        new_admin = session.get(User, username)
        if new_admin.admin == True:
            raise HTTPException(status_code=403, detail="User is already administrator.")
        else: 
            new_admin.admin = True
            session.commit()
            session.refresh(new_admin)
            return new_admin


@app.put("/items/add/{item_id}") 
async def add_item(session: SessionDep, # type: ignore
                item: Item,
                current_user: Annotated[User, Depends(get_current_active_user)]
):
    if verify_admin(current_user):
        item_found = session.get(Item, item.id)
        if item_found:
            return{"error: item_id %s already exists. Please use item serial number as unique identifier", item.id}
        else:            
            session.add(item)
            session.commit()
            session.refresh(item)
            verify = session.get(Item, item.id)
            if verify:
                return verify
            else: 
                raise HTTPException(status_code=400, detail="Bad request, unable to update database")
            
@app.delete("/items/delete/{item_id}")
async def delete_item(session: SessionDep, #type: ifnore
                      item_id: str,
                      current_user: Annotated[User, Depends(get_current_active_user)]
):
    if await verify_admin(current_user):
        item = await check_item(item_id, session)
        if item:
            session.delete(item)
            session.commit()
            session.refresh
            verify = session.get(Item, item_id)
            if verify: 
                raise HTTPException(status_code=400, detail="Something went wrong, could not remove item from database")
            else: 
                return("Item was deleted successfully.")

@app.get("/items/filter")
async def filter_items(
    session: SessionDep, # type: ignore
    availability: bool | None = Query(default=None),
    category: str | None = Query(default=None)
):
    query = select(Item)

    if availability is not None:
        query = query.where(Item.availability == availability)
    if category:
        query = query.where(Item.model == category)
    results = session.exec(query).all()
    return results

@app.get("/items/{item_id}")
async def get_item(
    session: SessionDep, # type: ignore
    item_id: str
):
    item = await check_item(item_id, session)
    return item
    
@app.put("/items/{item_id}/borrow")
async def borrow_item(
    session: SessionDep, # type: ignore
    item_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    user = current_user
    item = await check_item(item_id, session)
    if item.availability == False:
        raise HTTPException(status_code=403, detail="Forbidden operation, item is already borrowed.")
    item.availability = False
    id = item_id + str(datetime.now().timestamp()) #make a borrow id based on item borrowed and current time

    date_due = datetime.today() + item.borrow_period_days

    new_borrow = Borrow(
        borrow_id = id, 
        item_id = item_id,
        username = user.username,
        date_borrowed = datetime.today(),
        date_returned = None,
        date_due = date_due,
        active = True,
    )
    session.add(new_borrow)
    session.commit()
    session.refresh(item)
    await send_borrow_email(current_user.email, item.name, date_due)
    return{"Borrow confirmed. Borrow ID: %s", id}

@app.get("/user/borrows")
async def show_borrows(
    session: SessionDep, # type: ignore
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    user = current_user
    query = select(Borrow)
    query = query.where(Borrow.username == user.username)
    results = session.exec(query).all()
    return results

@app.get("/users/all/borrows")
async def show_borrow(
    session: SessionDep, # type: ignore
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    if await verify_admin(current_user):
        query = select(Borrow)
        results = session.exec(query).all()
        return results

@app.put("/items/{item_id}/return")
async def return_item(
    session: SessionDep, # type: ignore
    item_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    user = current_user
    borrow = session.exec(select(Borrow).where(
        Borrow.item_id == item_id, 
        Borrow.active == True, 
        Borrow.username == user.username)).first()
    if borrow == None:
        raise HTTPException(status_code=404, detail="Item is not found")
    item = session.get(Item, item_id)
    item.availability = True
    borrow.active = False
    borrow.date_returned = datetime.today()
    session.commit()
    session.refresh(item)
    return{"Return confirmed."}

@app.put("/items/{item_id}/damage-report")
async def report_damage(
    session: SessionDep, #type: ignore
    item_id: str,
    damage: str, 
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    user = current_user
    if await verify_admin(user):
        item = await check_item(item_id, session)
        item.damage = damage
        session.commit()
        session.refresh(item)
        return {"Damage logged."}





##### mock sample data for testing


def seed_sample(session):
    existing_users = session.exec(select(User)).all()
    if existing_users:
        return

    sample_users = [
        User(username="dzhanbyrshy", email="zhadi-25@rhodes.edu", full_name="Dimash Zhanbyrshy",
             hashed_password=get_password_hash("dz123"), user_id=0, admin=True),
        User(username="jhall", email="jh@example.com", full_name="Jules Hall",
             hashed_password=get_password_hash("jh123"), user_id=1, admin=False),
        User(username="egantulga", email="eg@example.com", full_name="EK Gantulga",
             hashed_password=get_password_hash("eg123"), user_id=2, admin=False)
    ]

    for user in sample_users:
        session.add(user)

    existing_items = session.exec(select(Item)).all()
    if existing_items:
        return  # Already seeded

    sample_items = [
        Item(name="Camera", id="0", description="DSLR camera", model="Canon EOS 90D",
            availability=True, borrow_period_days=timedelta(days=10), status="available"),
        Item(name="Tripod",  id="1", description="Adjustable tripod stand", model="Manfrotto Compact",
            availability=False, borrow_period_days=timedelta(days=14), status="borrowed"),
        Item(name="Whiteboard",  id="2", description="Magnetic whiteboard", model="Quartet",
            availability=True, borrow_period_days=timedelta(days=7), status="available"),
        Item(name="Microscope",  id="3", description="Science lab microscope", model="AmScope B120C",
            availability=False, borrow_period_days=timedelta(days=30), status="reserved"),
    ]

    for item in sample_items:
        session.add(item)

    session.commit()