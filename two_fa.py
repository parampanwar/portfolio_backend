# two_fa.py
import pyotp
import qrcode
import io
import base64
import secrets
from typing import List

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
    return totp.verify(token, valid_window=1)  # Allow 30s window

def generate_backup_codes(count: int = 8) -> List[str]:
    """Generate backup codes for account recovery"""
    return [secrets.token_hex(4).upper() for _ in range(count)]

def verify_backup_code(user_backup_codes: List[str], provided_code: str) -> tuple:
    """Verify backup code and remove it from the list"""
    if provided_code.upper() in user_backup_codes:
        user_backup_codes.remove(provided_code.upper())
        return True, user_backup_codes
    return False, user_backup_codes
