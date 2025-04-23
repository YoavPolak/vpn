from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt

# === App setup ===
app = FastAPI()

DATABASE_URL = "sqlite:///demo.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

# === Database Models ===
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)

class Token(Base):
    __tablename__ = "tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, nullable=False)
    username = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)

# === Pydantic Schemas ===
class UserSignup(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TokenValidation(BaseModel):
    token: str

# === Auth Service ===
class AuthService:
    def __init__(self, db: Session):
        self.db = db

    def hash_password(self, password: str) -> str:
        return pwd_context.hash(password)

    def verify_password(self, plain: str, hashed: str) -> bool:
        return pwd_context.verify(plain, hashed)

    def create_access_token(self, data: dict, expires_delta: timedelta) -> str:
        to_encode = data.copy()
        expire = datetime.utcnow() + expires_delta
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    def signup(self, username: str, email: str, password: str):
        if self.db.query(User).filter(User.username == username).first():
            raise HTTPException(status_code=400, detail="Username already exists")
        if self.db.query(User).filter(User.email == email).first():
            raise HTTPException(status_code=400, detail="Email already registered")

        hashed_password = self.hash_password(password)
        new_user = User(username=username, email=email, password=hashed_password)
        self.db.add(new_user)
        self.db.commit()

    def login(self, username: str, password: str) -> str:
        user = self.db.query(User).filter(User.username == username).first()
        if not user or not self.verify_password(password, user.password):
            raise HTTPException(status_code=401, detail="Invalid username or password")

        token = self.create_access_token(data={"sub": username}, expires_delta=timedelta(hours=1))
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

            return {
                "message": "Token is valid",
                "username": username,
                "expires_at": token_entry.expires_at.isoformat()
            }
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

# === DB Dependency ===
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# === Table Creation ===
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

# === Routes ===
@app.post("/signup")
def signup(user: UserSignup, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    try:
        auth_service.signup(user.username, user.email, user.password)
        return {"message": "User registered successfully"}
    except HTTPException as e:
        # Re-raise the error with its original status and detail
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except Exception as e:
        # Unexpected error (e.g., DB crash, etc.)
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    try:
        token = auth_service.login(user.username, user.password)
        return {"session_token": token}
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except Exception:
        raise HTTPException(status_code=500, detail="Login failed due to a server error")


@app.post("/validate_token")
def validate_token(data: TokenValidation, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    try:
        return auth_service.validate_token(data.token)
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except Exception:
        raise HTTPException(status_code=500, detail="Token validation failed")
