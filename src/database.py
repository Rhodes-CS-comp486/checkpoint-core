from sqlmodel import Field, Session, SQLModel, create_engine

f = open('db//password.txt', 'r')
password = f.readline()
password.strip()

engine = create_engine("postgresql://postgres:postgres@db:5432/checkpoint-db", echo=True)
SessionLocal = engine.connect()

class User(SQLModel, table=True):
    username: str = Field(primary_key=True, index=True)
    email: str = Field(index=True, unique=True)
    full_name: str 
    hashed_password: str
    admin: bool = Field(default=False)

class Item(SQLModel, table=True):
    id: int = Field(primary_key=True, index=True)
    name: str = Field(index=True)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
