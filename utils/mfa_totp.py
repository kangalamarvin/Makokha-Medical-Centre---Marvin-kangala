"""
Multi-Factor Authentication (TOTP) Module
Provides Time-based One-Time Password authentication using Google Authenticator,
Authy, or any TOTP-compatible app.

Security Features:
- TOTP with 30-second time window
- 6-digit codes
- Backup codes for account recovery
- QR code generation for easy setup
- Rate limiting protection
"""

import pyotp
import qrcode
from io import BytesIO
import base64
import secrets
import json
from typing import Tuple, List, Optional
from datetime import datetime, timedelta


class MFAManager:
    """Manage TOTP Multi-Factor Authentication for users"""
    
    @staticmethod
    def generate_totp_secret() -> str:
        """
        Generate a new TOTP secret key for a user.
        
        Returns:
            Base32-encoded secret key
        """
        return pyotp.random_base32()
    
    @staticmethod
    def generate_backup_codes(count: int = 10) -> List[str]:
        """
        Generate backup codes for account recovery.
        
        Args:
            count: Number of backup codes to generate (default: 10)
            
        Returns:
            List of backup codes (format: XXXX-XXXX-XXXX-XXXX)
        """
        backup_codes = []
        for _ in range(count):
            # Generate 16-character code in groups of 4
            code = '-'.join([
                secrets.token_hex(2).upper()
                for _ in range(4)
            ])
            backup_codes.append(code)
        return backup_codes
    
    @staticmethod
    def get_totp_uri(secret: str, user_email: str, issuer: str = "Makokha Medical Centre") -> str:
        """
        Generate TOTP provisioning URI for QR code.
        
        Args:
            secret: User's TOTP secret key
            user_email: User's email address
            issuer: Application name
            
        Returns:
            TOTP provisioning URI
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=user_email,
            issuer_name=issuer
        )
    
    @staticmethod
    def generate_qr_code(totp_uri: str) -> str:
        """
        Generate QR code image for TOTP setup.
        
        Args:
            totp_uri: TOTP provisioning URI
            
        Returns:
            Base64-encoded PNG image
        """
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    @staticmethod
    def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
        """
        Verify a TOTP code.
        
        Args:
            secret: User's TOTP secret key
            code: 6-digit code from authenticator app
            window: Number of time steps to check (1 = ±30 seconds)
            
        Returns:
            True if code is valid, False otherwise
        """
        if not code or len(code) != 6 or not code.isdigit():
            return False
        
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(code, valid_window=window)
        except Exception:
            return False
    
    @staticmethod
    def hash_backup_code(code: str) -> str:
        """
        Hash a backup code for secure storage.
        Uses the same hashing mechanism as passwords.
        
        Args:
            code: Plain backup code
            
        Returns:
            Hashed backup code
        """
        from werkzeug.security import generate_password_hash
        return generate_password_hash(code)
    
    @staticmethod
    def verify_backup_code(stored_hash: str, code: str) -> bool:
        """
        Verify a backup code against its hash.
        
        Args:
            stored_hash: Stored hash of backup code
            code: User-provided backup code
            
        Returns:
            True if code matches, False otherwise
        """
        from werkzeug.security import check_password_hash
        return check_password_hash(stored_hash, code)
    
    @staticmethod
    def get_current_totp_code(secret: str) -> str:
        """
        Get the current TOTP code (for testing/debugging only).
        DO NOT expose this to users in production!
        
        Args:
            secret: TOTP secret key
            
        Returns:
            Current 6-digit TOTP code
        """
        totp = pyotp.TOTP(secret)
        return totp.now()


class MFASession:
    """Manage MFA session state during login"""
    
    def __init__(self):
        self.mfa_pending = {}  # {session_id: {'user_id': int, 'expires': datetime}}
    
    def create_mfa_session(self, user_id: int, duration_minutes: int = 5) -> str:
        """
        Create temporary MFA session during login.
        
        Args:
            user_id: User ID pending MFA verification
            duration_minutes: Session validity duration
            
        Returns:
            Session ID
        """
        session_id = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(minutes=duration_minutes)
        
        self.mfa_pending[session_id] = {
            'user_id': user_id,
            'expires': expires,
            'attempts': 0
        }
        
        # Clean up expired sessions
        self._cleanup_expired()
        
        return session_id
    
    def verify_mfa_session(self, session_id: str) -> Optional[int]:
        """
        Verify MFA session and return user ID.
        
        Args:
            session_id: MFA session ID
            
        Returns:
            User ID if valid, None if invalid/expired
        """
        if session_id not in self.mfa_pending:
            return None
        
        session = self.mfa_pending[session_id]
        
        if datetime.utcnow() > session['expires']:
            del self.mfa_pending[session_id]
            return None
        
        return session['user_id']
    
    def increment_attempts(self, session_id: str) -> int:
        """Increment failed MFA attempts."""
        if session_id in self.mfa_pending:
            self.mfa_pending[session_id]['attempts'] += 1
            return self.mfa_pending[session_id]['attempts']
        return 0
    
    def complete_mfa_session(self, session_id: str):
        """Remove MFA session after successful verification."""
        if session_id in self.mfa_pending:
            del self.mfa_pending[session_id]
    
    def _cleanup_expired(self):
        """Remove expired MFA sessions."""
        now = datetime.utcnow()
        expired = [sid for sid, data in self.mfa_pending.items() if now > data['expires']]
        for sid in expired:
            del self.mfa_pending[sid]


# Global MFA session manager
mfa_session_manager = MFASession()


# Utility functions for easy use
def setup_user_mfa(user_email: str) -> Tuple[str, List[str], str]:
    """
    Setup MFA for a user.
    
    Args:
        user_email: User's email address
        
    Returns:
        Tuple of (secret_key, backup_codes, qr_code_data_uri)
    """
    secret = MFAManager.generate_totp_secret()
    backup_codes = MFAManager.generate_backup_codes()
    totp_uri = MFAManager.get_totp_uri(secret, user_email)
    qr_code = MFAManager.generate_qr_code(totp_uri)
    
    return secret, backup_codes, qr_code


def verify_mfa_code(secret: str, code: str) -> bool:
    """
    Quick function to verify TOTP code.
    
    Args:
        secret: User's TOTP secret
        code: 6-digit TOTP code
        
    Returns:
        True if valid, False otherwise
    """
    return MFAManager.verify_totp_code(secret, code)


# Example usage:
# 
# # Setup MFA for user
# secret, backup_codes, qr_code = setup_user_mfa("user@example.com")
# # Store secret in database (encrypted)
# # Store hashed backup codes in database
# # Display QR code to user
#
# # Verify MFA code during login
# is_valid = verify_mfa_code(secret, "123456")
