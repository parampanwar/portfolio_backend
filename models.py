# models.py
from beanie import Document
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

class User(Document):
    email: EmailStr
    hashed_password: str
    is_active: bool = True
    is_admin: bool = False
    created_at: datetime = datetime.utcnow()
    
    # 2FA Fields
    two_fa_enabled: bool = False
    two_fa_secret: Optional[str] = None
    backup_codes: Optional[List[str]] = []
    
    class Settings:
        name = "users"

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    is_admin: bool = False

class UserOut(BaseModel):
    id: str
    email: EmailStr
    is_active: bool
    is_admin: bool
    created_at: datetime
    two_fa_enabled: bool

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserOut

class TwoFASetup(BaseModel):
    qr_code_url: str
    secret: str
    backup_codes: List[str]

class TwoFAVerify(BaseModel):
    token: str

class LoginWithTwoFA(BaseModel):
    email: str
    password: str
    two_fa_token: Optional[str] = None

# Resume model

class Resume(Document):
    filename: str = "parampanwar"
    original_name: str
    file_data: bytes  # Store PDF data in MongoDB
    file_size: int
    content_type: str = "application/pdf"
    uploaded_at: datetime = datetime.utcnow()
    is_active: bool = True
    version: int = 1
    
    class Settings:
        name = "resumes"

class ResumeOut(BaseModel):
    id: str
    filename: str
    original_name: str
    file_size: int
    uploaded_at: datetime
    is_active: bool
    version: int
    download_url: str

