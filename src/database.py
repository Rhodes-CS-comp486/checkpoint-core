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
    password: str #stored here as a hash, sent from client as plaintext
    admin: bool = Field(default=False)

class Item(SQLModel, table=True):
    id: int = Field(primary_key=True, index=True)
    name: str = Field(index=True)
    description: str = Field()
    model: str = Field()
    availability: bool = Field() #available is true, unavailable is false
    status: str = Field()

    #joined table for history 

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
