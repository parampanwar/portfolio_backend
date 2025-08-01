# main.py
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional, List
import os
from dotenv import load_dotenv
import pyotp
import qrcode
import io
import base64
import secrets
from pydantic import BaseModel
import shutil
import uuid
from pathlib import Path
import base64


# Import your existing modules
from database import init_db
from models import User, UserCreate, Token, UserOut,  LoginWithTwoFA, Resume, ResumeOut


load_dotenv()

app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security constants from .env
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


# --- 2FA Utility Functions ---

def generate_secret() -> str:
    """Generate a new secret for TOTP"""
    return pyotp.random_base32()

def generate_qr_code(email: str, secret: str, issuer: str = "YourApp") -> str:
    """Generate QR code for Microsoft Authenticator"""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=issuer
    )
    
    # Create QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    # Convert to base64 image
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    # Return base64 encoded image
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_base64}"

def verify_token(secret: str, token: str) -> bool:
    """Verify TOTP token from Microsoft Authenticator"""
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=2)  # Allow 30s window

def generate_backup_codes(count: int = 8) -> List[str]:
    """Generate backup codes for account recovery"""
    return [secrets.token_hex(4).upper() for _ in range(count)]

def verify_backup_code(user_backup_codes: List[str], provided_code: str) -> tuple:
    """Verify backup code and remove it from the list"""
    if provided_code.upper() in user_backup_codes:
        user_backup_codes.remove(provided_code.upper())
        return True, user_backup_codes
    return False, user_backup_codes

# --- Utility Functions (Updated for DB) ---

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_user(email: str) -> Optional[User]:
    """Finds a user by email in the database."""
    return await User.find_one(User.email == email)

async def authenticate_user(email: str, password: str) -> Optional[User]:
    """Authenticates a user by checking email and verifying password."""
    user = await get_user(email)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Dependencies ---

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await get_user(email=email)
    if user is None:
        raise credentials_exception
    return user

async def get_current_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to ensure current user is an admin."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions. Admin access required."
        )
    return current_user

# --- Event Handler to Initialize DB ---

@app.on_event("startup")
async def on_startup():
    await init_db()

# --- Authentication Routes ---

@app.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register_user(user_in: UserCreate):
    """Handles user registration."""
    existing_user = await get_user(user_in.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    
    hashed_password = get_password_hash(user_in.password)
    user = User(
        email=user_in.email, 
        hashed_password=hashed_password,
        is_admin=user_in.is_admin,
        created_at=datetime.utcnow()
    )
    await user.insert()
    
    return UserOut(
        id=str(user.id), 
        email=user.email, 
        is_active=user.is_active,
        is_admin=user.is_admin,
        created_at=user.created_at,
        two_fa_enabled=user.two_fa_enabled
    )

@app.post("/auth/login")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login route that handles both regular and 2FA-enabled users"""
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if 2FA is enabled
    if user.two_fa_enabled:
        # Return special response indicating 2FA is required
        return {
            "requires_2fa": True,
            "message": "2FA token required",
            "email": user.email
        }
    
    # Normal login flow for users without 2FA
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    user_out = UserOut(
        id=str(user.id), 
        email=user.email, 
        is_active=user.is_active,
        is_admin=user.is_admin,
        created_at=user.created_at,
        two_fa_enabled=user.two_fa_enabled
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_out
    }

@app.post("/auth/login/2fa", response_model=Token)
async def login_with_two_fa(request: LoginWithTwoFA):
    """Complete login with 2FA token"""
    # First verify email/password
    user = await authenticate_user(request.email, request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    if not user.two_fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled for this account"
        )
    
    # Check if it's a backup code (8 characters)
    if len(request.two_fa_token) == 8:
        is_valid, updated_codes = verify_backup_code(user.backup_codes, request.two_fa_token)
        if is_valid:
            user.backup_codes = updated_codes
            await user.save()
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid backup code"
            )
    else:
        # Verify TOTP token (6 digits)
        if not verify_token(user.two_fa_secret, request.two_fa_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA token"
            )
    
    # Generate JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    user_out = UserOut(
        id=str(user.id), 
        email=user.email, 
        is_active=user.is_active,
        is_admin=user.is_admin,
        created_at=user.created_at,
        two_fa_enabled=user.two_fa_enabled
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_out
    }



@app.get("/auth/me", response_model=UserOut)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """Returns the current authenticated user's details."""
    return UserOut(
        id=str(current_user.id), 
        email=current_user.email, 
        is_active=current_user.is_active,
        is_admin=current_user.is_admin,
        created_at=current_user.created_at,
        two_fa_enabled=current_user.two_fa_enabled
    )

# --- 2FA Routes ---

@app.post("/auth/2fa/setup")
async def setup_two_fa(current_user: User = Depends(get_current_user)):
    """Setup 2FA for the current user"""
    if current_user.two_fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is already enabled for this account"
        )
    
    # Generate secret and backup codes
    secret = generate_secret()
    backup_codes = generate_backup_codes()
    
    # Generate QR code for Microsoft Authenticator
    qr_code_url = generate_qr_code(current_user.email, secret, "YourApp")
    
    # Save secret to user (but don't enable 2FA yet)
    current_user.two_fa_secret = secret
    current_user.backup_codes = backup_codes
    await current_user.save()
    
    return {
        "qr_code_url": qr_code_url,
        "secret": secret,
        "backup_codes": backup_codes
    }

@app.post("/auth/2fa/verify-setup")
async def verify_two_fa_setup(
    token: str,
    current_user: User = Depends(get_current_user)
):
    """Verify 2FA setup by confirming a token from Microsoft Authenticator"""
    if current_user.two_fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is already enabled"
        )
    
    if not current_user.two_fa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA setup not initiated. Please start setup first."
        )
    
    # Verify the token
    if not verify_token(current_user.two_fa_secret, token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token. Please try again."
        )
    
    # Enable 2FA
    current_user.two_fa_enabled = True
    await current_user.save()
    
    return {
        "message": "2FA successfully enabled!", 
        "backup_codes": current_user.backup_codes
    }

@app.post("/auth/2fa/disable")
async def disable_two_fa(
    token: str,
    current_user: User = Depends(get_current_user)
):
    """Disable 2FA for the current user"""
    if not current_user.two_fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled"
        )
    
    # Verify current token before disabling
    if not verify_token(current_user.two_fa_secret, token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token"
        )
    
    # Disable 2FA
    current_user.two_fa_enabled = False
    current_user.two_fa_secret = None
    current_user.backup_codes = []
    await current_user.save()
    
    return {"message": "2FA successfully disabled"}

@app.get("/auth/2fa/status")
async def get_2fa_status(current_user: User = Depends(get_current_user)):
    """Get 2FA status for current user"""
    return {
        "two_fa_enabled": current_user.two_fa_enabled,
        "backup_codes_remaining": len(current_user.backup_codes) if current_user.backup_codes else 0
    }

# --- Admin Routes ---

@app.get("/admin/users", response_model=List[UserOut])
async def get_all_users_admin(current_admin: User = Depends(get_current_admin_user)):
    """Get all users (admin only)."""
    users = await User.find_all().to_list()
    return [
        UserOut(
            id=str(user.id),
            email=user.email,
            is_active=user.is_active,
            is_admin=user.is_admin,
            created_at=user.created_at,
            two_fa_enabled=user.two_fa_enabled
        )
        for user in users
    ]

@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, current_admin: User = Depends(get_current_admin_user)):
    """Delete a user (admin only)."""
    from bson import ObjectId
    
    # Don't allow admin to delete themselves
    if str(current_admin.id) == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    try:
        user_to_delete = await User.get(ObjectId(user_id))
        if not user_to_delete:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        await user_to_delete.delete()
        return {"message": "User deleted successfully"}
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

@app.put("/admin/users/{user_id}/toggle-admin")
async def toggle_user_admin_status(user_id: str, current_admin: User = Depends(get_current_admin_user)):
    """Toggle admin status of a user (admin only)."""
    from bson import ObjectId
    
    # Don't allow admin to remove their own admin status
    if str(current_admin.id) == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot modify your own admin status"
        )
    
    try:
        user = await User.get(ObjectId(user_id))
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user.is_admin = not user.is_admin
        await user.save()
        
        return {
            "message": f"User admin status {'granted' if user.is_admin else 'revoked'}",
            "user": UserOut(
                id=str(user.id),
                email=user.email,
                is_active=user.is_active,
                is_admin=user.is_admin,
                created_at=user.created_at,
                two_fa_enabled=user.two_fa_enabled
            )
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

@app.post("/admin/users/{user_id}/disable-2fa")
async def admin_disable_user_2fa(user_id: str, current_admin: User = Depends(get_current_admin_user)):
    """Admin can disable 2FA for any user (emergency access)"""
    from bson import ObjectId
    
    try:
        user = await User.get(ObjectId(user_id))
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if not user.two_fa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA is not enabled for this user"
            )
        
        # Disable 2FA
        user.two_fa_enabled = False
        user.two_fa_secret = None
        user.backup_codes = []
        await user.save()
        
        return {"message": f"2FA disabled for user {user.email}"}
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

# --- Root Route ---

@app.get("/")
async def root():
    return {"message": "FastAPI Authentication Server with MongoDB, Beanie, and 2FA"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


@app.get("/debug/user/{email}")
async def debug_user_2fa(email: str):
    """Debug 2FA data for a user"""
    user = await get_user(email)
    if not user:
        return {"error": "User not found"}
    
    return {
        "email": user.email,
        "two_fa_enabled": user.two_fa_enabled,
        "has_secret": bool(user.two_fa_secret),
        "secret_length": len(user.two_fa_secret) if user.two_fa_secret else 0,
        "backup_codes_count": len(user.backup_codes) if user.backup_codes else 0,
        "backup_codes": user.backup_codes[:3] if user.backup_codes else [],  # Show first 3 for verification
        "created_at": user.created_at
    }


@app.post("/admin/reset-2fa/{email}")
async def reset_2fa(email: str):
    """Reset 2FA for debugging"""
    user = await get_user(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Reset 2FA completely
    user.two_fa_enabled = False
    user.two_fa_secret = None
    user.backup_codes = []
    await user.save()
    
    return {"message": f"2FA reset for {email}"}



#Resumes backend code
@app.get("/api/resumes", response_model=List[ResumeOut])
async def get_all_resumes():
    """Get all active resumes(public endpoint for dashboard)"""
    resumes = await Resume.find(Resume.is_active == True).sort(-Resume.uploaded_at).to_list()
    return[
        ResumeOut(
            id=str(resume.id),
            filename=resume.filename,
            original_name=resume.original_name,
            file_size=resume.file_size,
            uploaded_at=resume.uploaded_at,
            is_active=resume.is_active,
            version=resume.version,
            download_url=f"/api/resumes/{str(resume.id)}/download"
        )
        for resume in resumes
    ] 
@app.post("/api/upload-resume")
async def upload_resume(
    resume: UploadFile = File(...),
    current_admin: User = Depends(get_current_admin_user)
):
    """Upload a new resume (admin only) - Always saves as 'parampanwar'"""
    
    if not resume.filename.lower().endswith('.pdf'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PDF files are allowed"
        )
    
    try:
        # Read file data
        file_data = await resume.read()
        
        # Check if a resume already exists
        existing_resume = await Resume.find_one(Resume.is_active == True)
        
        if existing_resume:
            # Update existing resume (mark old as inactive)
            existing_resume.is_active = False
            await existing_resume.save()
            new_version = existing_resume.version + 1
        else:
            new_version = 1
        
        # Create new resume record - 🔥 REMOVED file_path
        new_resume = Resume(
            filename="parampanwar",
            original_name=resume.filename,
            file_data=file_data,
            file_size=len(file_data),
            content_type="application/pdf",
            uploaded_at=datetime.utcnow(),
            is_active=True,
            version=new_version
        )
        await new_resume.insert()
        
        return ResumeOut(
            id=str(new_resume.id),
            filename=new_resume.filename,
            original_name=new_resume.original_name,
            file_size=new_resume.file_size,
            uploaded_at=new_resume.uploaded_at,
            is_active=new_resume.is_active,
            version=new_resume.version,
            download_url=f"/api/resumes/{str(new_resume.id)}/download"
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload file: {str(e)}"
        )
@app.get("/api/resumes/{resume_id}/download")
async def download_resume(resume_id: str):
    """Download resume by ID"""
    from bson import ObjectId
    
    try:
        resume = await Resume.get(ObjectId(resume_id))
        if not resume or not resume.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Resume not found"
            )
        
        # Return PDF file with consistent filename
        return Response(
            content=resume.file_data,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=parampanwar.pdf"
            }
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resume not found"
        )

@app.get("/api/resumes/{resume_id}/view")
async def view_resume(resume_id: str):
    """View resume in browser"""
    from bson import ObjectId
    
    try:
        resume = await Resume.get(ObjectId(resume_id))
        if not resume or not resume.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Resume not found"
            )
        
        # Return PDF file for viewing
        return Response(
            content=resume.file_data,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"inline; filename=parampanwar.pdf"
            }
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resume not found"
        )

@app.delete("/api/resumes/{resume_id}")
async def delete_resume(
    resume_id: str,
    current_admin: User = Depends(get_current_admin_user)
):
    """Delete a resume (admin only) - Marks as inactive"""
    from bson import ObjectId
    
    try:
        resume = await Resume.get(ObjectId(resume_id))
        if not resume:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Resume not found"
            )
        
        # Mark as inactive instead of deleting
        resume.is_active = False
        await resume.save()
        
        return {"message": "Resume deleted successfully"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resume not found"
        )

@app.get("/api/resumes/current")
async def get_current_resume():
    """Get the current active resume (public endpoint)"""
    resume = await Resume.find_one(Resume.is_active == True, sort=[("uploaded_at", -1)])
    
    if not resume:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No resume found"
        )
    
    return ResumeOut(
        id=str(resume.id),
        filename=resume.filename,
        original_name=resume.original_name,
        file_size=resume.file_size,
        uploaded_at=resume.uploaded_at,
        is_active=resume.is_active,
        version=resume.version,
        download_url=f"/api/resumes/{str(resume.id)}/download"
    )
