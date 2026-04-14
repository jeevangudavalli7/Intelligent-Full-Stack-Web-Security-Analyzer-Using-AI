from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
import os

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", "devsecret")
ALGORITHM = "HS256"

class UserRegister(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

# Fake user db
fake_users_db = {}

@router.post("/register")
async def register(user: UserRegister):
    if user.email in fake_users_db:
        raise HTTPException(400, "Email already registered")
    hashed = pwd_context.hash(user.password)
    fake_users_db[user.email] = {"email": user.email, "password": hashed}
    return {"message": "User created"}

@router.post("/login", response_model=TokenResponse)
async def login(user: UserLogin):
    db_user = fake_users_db.get(user.email)
    if not db_user or not pwd_context.verify(user.password, db_user["password"]):
        raise HTTPException(401, "Invalid credentials")
    expire = datetime.utcnow() + timedelta(hours=1)
    token = jwt.encode({"sub": user.email, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    return TokenResponse(access_token=token, expires_in=3600)