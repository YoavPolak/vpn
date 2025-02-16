from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt

# Initialize FastAPI app
app = FastAPI()

# SQLite database setup
DATABASE_URL = "sqlite:///demo.db"  # SQLite database file (demo.db)
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})  # SQLite-specific argument
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT secret and algorithm
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

# Models for database
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)

class Token(Base):
    __tablename__ = "tokens"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    token = Column(String, unique=True, nullable=False)
    username = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)

# Pydantic models
class UserSignup(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TokenValidation(BaseModel):
    token: str

# Utility class
class AuthService:
    def __init__(self, db: Session):
        self.db = db

    def hash_password(self, password: str) -> str:
        return pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    def create_access_token(self, data: dict, expires_delta: timedelta) -> str:
        to_encode = data.copy()
        expire = datetime.utcnow() + expires_delta
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    def signup(self, username: str, password: str):
        if self.db.query(User).filter(User.username == username).first():
            raise HTTPException(status_code=400, detail="Username already exists")
        hashed_password = self.hash_password(password)
        new_user = User(username=username, password=hashed_password)
        self.db.add(new_user)
        self.db.commit()

    def login(self, username: str, password: str) -> str:
        user = self.db.query(User).filter(User.username == username).first()
        if not user or not self.verify_password(password, user.password):
            raise HTTPException(status_code=400, detail="Invalid username or password")
        token = self.create_access_token(
            data={"sub": username},
            expires_delta=timedelta(hours=1)
        )
        expires_at = datetime.utcnow() + timedelta(hours=1)
        token_entry = Token(token=token, username=username, expires_at=expires_at)
        self.db.add(token_entry)
        self.db.commit()
        return token

    def validate_token(self, token: str):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            token_entry = self.db.query(Token).filter(Token.token == token).first()
            if not token_entry or token_entry.expires_at < datetime.utcnow():
                raise HTTPException(status_code=401, detail="Token expired or invalid")

            # If the token is valid, include the expiration time in the response
            expiration_time = token_entry.expires_at.isoformat()  # Assuming `expires_at` is a datetime object
            return {
                "message": "Token is valid",
                "expirationTime": expiration_time
            }

        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create tables on startup
@app.on_event("startup")
def on_startup():
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)

@app.post("/signup")
def signup(user: UserSignup, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    auth_service.signup(user.username, user.password)
    return {"message": "User registered successfully"}

@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    token = auth_service.login(user.username, user.password)
    return {"session_token": token}

@app.post("/validate_token")
def validate_token(data: TokenValidation, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    return auth_service.validate_token(data.token)
