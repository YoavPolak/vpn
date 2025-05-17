# === Imports ===
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, validator
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import asyncio
import re
import threading
from email_validator import validate_email, EmailNotValidError

# === FastAPI App Initialization ===
app = FastAPI()

# === SQLite Database Configuration ===
DATABASE_URL = "sqlite:///users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# === Cryptography Setup ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

# === Lock for Thread-Safe DB Access ===
db_lock = threading.Lock()

# === SQLAlchemy Models ===
class User(Base):
    """Database model for user records."""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)

class Token(Base):
    """Database model for storing access tokens."""
    __tablename__ = "tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, nullable=False)
    username = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)

# === Pydantic Schemas for Input Validation ===

class UserSignup(BaseModel):
    """Schema for user signup request."""
    username: str
    email: str
    password: str

    @validator('username')
    def validate_username(cls, value):
        if len(value) < 4:
            raise HTTPException(status_code=400, detail="Username must be at least 4 characters long")
        if not re.match(r"^\w+$", value):
            raise HTTPException(status_code=400, detail="Username must contain only letters, numbers, and underscores")
        if any(c in value for c in [";", "'", "--"]):
            raise HTTPException(status_code=400, detail="Username contains disallowed characters")
        return value

    @validator('email')
    def validate_email_format(cls, value):
        try:
            validate_email(value)
            return value
        except EmailNotValidError as e:
            raise HTTPException(status_code=400, detail=f"Invalid email format: {e}")

    @validator('password')
    def validate_password(cls, value):
        if len(value) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", value):
            raise HTTPException(status_code=400, detail="Password must include at least one uppercase letter")
        if not re.search(r"[a-z]", value):
            raise HTTPException(status_code=400, detail="Password must include at least one lowercase letter")
        if not re.search(r"\d", value):
            raise HTTPException(status_code=400, detail="Password must include at least one digit")
        return value

class UserLogin(BaseModel):
    """Schema for user login request."""
    username: str
    password: str

    @validator('username')
    def validate_username(cls, value):
        if not re.match(r"^\w+$", value):
            raise HTTPException(status_code=400, detail="Username must contain only letters, numbers, and underscores")
        if any(s in value for s in [";", "'", "--", "/*", "*/"]):
            raise HTTPException(status_code=400, detail="Username contains disallowed characters")
        return value

    @validator('password')
    def validate_password(cls, value):
        if any(s in value for s in [";", "'", "--", "/*", "*/"]):
            raise HTTPException(status_code=400, detail="Password contains disallowed characters")
        return value

class TokenValidation(BaseModel):
    """Schema for token validation request."""
    token: str

# === Authentication Service Class ===

class AuthService:
    """
    Service class handling all authentication logic:
    - Signup
    - Login
    - Password hashing
    - JWT token management
    """
    def __init__(self, db: Session):
        self.db = db

    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        return pwd_context.hash(password)

    def verify_password(self, plain: str, hashed: str) -> bool:
        """Verify a plain password against a hashed one."""
        return pwd_context.verify(plain, hashed)

    def create_access_token(self, data: dict, expires_delta: timedelta) -> str:
        """Generate a JWT token with expiration."""
        to_encode = data.copy()
        expire = datetime.utcnow() + expires_delta
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    def signup(self, username: str, email: str, password: str):
        """Register a new user."""
        try:
            # Ensure user/email doesn't already exist
            if self.db.query(User).filter(User.username == username).first():
                raise HTTPException(status_code=400, detail="Username already exists")
            if self.db.query(User).filter(User.email == email).first():
                raise HTTPException(status_code=400, detail="Email already registered")

            hashed_password = self.hash_password(password)
            new_user = User(username=username, email=email, password=hashed_password)

            with db_lock:
                self.db.add(new_user)
                self.db.commit()
        except HTTPException:
            raise
        except Exception as e:
            print(f"[ERROR] Signup failed: {e}")
            raise HTTPException(status_code=500, detail="User signup failed")

    def login(self, username: str, password: str) -> str:
        """Authenticate user and return access token."""
        try:
            user = self.db.query(User).filter(User.username == username).first()
            if not user or not self.verify_password(password, user.password):
                raise HTTPException(status_code=401, detail="Invalid username or password")

            token = self.create_access_token(data={"sub": username}, expires_delta=timedelta(hours=1))
            expires_at = datetime.utcnow() + timedelta(hours=1)

            with db_lock:
                token_entry = Token(token=token, username=username, expires_at=expires_at)
                self.db.add(token_entry)
                self.db.commit()

            return token
        except HTTPException:
            raise
        except Exception as e:
            print(f"[ERROR] Login failed: {e}")
            raise HTTPException(status_code=500, detail="Login failed due to a server error")

    def validate_token(self, token: str):
        """Validate a token and ensure it hasn't expired."""
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
        except Exception as e:
            print(f"[ERROR] Token validation failed: {e}")
            raise HTTPException(status_code=500, detail="Token validation failed")

# === Dependency to Get DB Session ===
def get_db():
    """Yield a database session for dependency injection."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# === Startup Hook: Create Tables ===
@app.on_event("startup")
def on_startup():
    """Initialize tables on app startup."""
    Base.metadata.create_all(bind=engine)

# === Startup Hook: Background Token Cleanup ===
@app.on_event("startup")
async def start_token_cleanup_task():
    """
    Launches a background coroutine to clean up expired tokens
    every hour.
    """
    async def cleanup_expired_tokens():
        while True:
            db = SessionLocal()
            try:
                now = datetime.utcnow()
                with db_lock:
                    db.query(Token).filter(Token.expires_at < now).delete()
                    db.commit()
            except Exception as e:
                print(f"[ERROR] Token cleanup failed: {e}")
            finally:
                db.close()
                print("Cleaned expired tokens.")
            await asyncio.sleep(3600)

    asyncio.create_task(cleanup_expired_tokens())

# === Routes ===

@app.post("/signup")
def signup(user: UserSignup, db: Session = Depends(get_db)):
    """API endpoint to register a new user."""
    auth_service = AuthService(db)
    auth_service.signup(user.username, user.email, user.password)
    return {"message": "User registered successfully"}

@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    """API endpoint for user login."""
    auth_service = AuthService(db)
    token = auth_service.login(user.username, user.password)
    return {"session_token": token}

@app.post("/validate_token")
def validate_token(data: TokenValidation, db: Session = Depends(get_db)):
    """API endpoint to validate JWT token."""
    auth_service = AuthService(db)
    return auth_service.validate_token(data.token)