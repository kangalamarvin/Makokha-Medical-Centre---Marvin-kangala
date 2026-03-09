from flask import current_app
import base64
from cryptography.fernet import Fernet, InvalidToken
from functools import wraps

class EncryptionUtils:
    fernet = None

    @classmethod
    def init_fernet(cls, app):
        """Initialize Fernet with key from app config"""
        key = app.config.get('FERNET_KEY')
        if not key:
            raise ValueError("No FERNET_KEY set in configuration")
        cls.fernet = Fernet(key.encode())

    @classmethod
    def encrypt_data(cls, data):
        """Encrypt data with proper error handling"""
        if not data or not isinstance(data, str):
            return ""
            
        try:
            if cls.fernet is None:
                raise ValueError("Fernet not initialized")
            return cls.fernet.encrypt(data.encode()).decode()
        except InvalidToken as e:
            current_app.logger.error(f"Encryption failed - invalid token: {str(e)}")
            return ""
        except Exception as e:
            current_app.logger.error(f"Encryption failed: {str(e)}")
            return ""

    @classmethod
    def decrypt_data(cls, encrypted_data):
        """Decrypt data with proper error handling"""
        if not encrypted_data or not isinstance(encrypted_data, str):
            return ""
            
        try:
            if cls.fernet is None:
                raise ValueError("Fernet not initialized")
            return cls.fernet.decrypt(encrypted_data.encode()).decode()
        except InvalidToken as e:
            current_app.logger.error(f"Decryption failed - invalid token: {str(e)}. Possible key mismatch or tampered data. Manual key rotation may be required.")
            return "[Decryption Error: Invalid Token]"
        except Exception as e:
            current_app.logger.error(f"Decryption failed: {str(e)}")
            return "[Decryption Error]"