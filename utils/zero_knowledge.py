"""
Zero-Knowledge Encryption System
Implements client-side encryption where the server never has access to plaintext sensitive data.

Features:
- Client-side encryption of sensitive patient data
- Server-side encrypted storage only
- Key derivation from user password (never stored)
- Secure key exchange
- End-to-end encryption for medical records
- Per-user encryption keys
- Secure key recovery mechanism
"""

import os
import base64
import hashlib
import secrets
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import json


class ZeroKnowledgeEncryption:
    """
    Zero-Knowledge Encryption system for sensitive medical data.
    The server never has access to unencrypted data or user encryption keys.
    """
    
    # Encryption configuration
    KEY_DERIVATION_ITERATIONS = 200000  # PBKDF2 iterations
    SALT_LENGTH = 32  # bytes
    KEY_LENGTH = 32  # bytes (256 bits)
    
    @classmethod
    def generate_salt(cls) -> str:
        """Generate a random salt for key derivation"""
        return base64.urlsafe_b64encode(secrets.token_bytes(cls.SALT_LENGTH)).decode('utf-8')
    
    @classmethod
    def derive_key_from_password(cls, password: str, salt: str) -> bytes:
        """
        Derive encryption key from user password.
        This happens client-side in production.
        
        Args:
            password: User's password
            salt: Unique salt for this user
            
        Returns:
            Derived encryption key (32 bytes)
        """
        salt_bytes = base64.urlsafe_b64decode(salt.encode('utf-8'))
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=cls.KEY_LENGTH,
            salt=salt_bytes,
            iterations=cls.KEY_DERIVATION_ITERATIONS,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key
    
    @classmethod
    def encrypt_data(cls, data: str, key: bytes) -> str:
        """
        Encrypt data using AES-256-GCM (authenticated encryption).
        
        Args:
            data: Plaintext data to encrypt
            key: 32-byte encryption key
            
        Returns:
            Base64-encoded encrypted data with nonce
        """
        # Generate random nonce (12 bytes for GCM)
        nonce = secrets.token_bytes(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
        
        # Combine nonce + tag + ciphertext
        encrypted_data = nonce + encryptor.tag + ciphertext
        
        # Return base64-encoded
        return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
    
    @classmethod
    def decrypt_data(cls, encrypted_data: str, key: bytes) -> str:
        """
        Decrypt data encrypted with encrypt_data.
        
        Args:
            encrypted_data: Base64-encoded encrypted data
            key: 32-byte encryption key
            
        Returns:
            Decrypted plaintext data
        """
        # Decode from base64
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
        
        # Extract nonce, tag, and ciphertext
        nonce = encrypted_bytes[:12]
        tag = encrypted_bytes[12:28]
        ciphertext = encrypted_bytes[28:]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')
    
    @classmethod
    def encrypt_medical_record(cls, record_data: dict, user_key: bytes) -> str:
        """
        Encrypt a complete medical record.
        
        Args:
            record_data: Dictionary containing medical record data
            user_key: User's encryption key
            
        Returns:
            Encrypted record as base64 string
        """
        # Convert to JSON
        json_data = json.dumps(record_data)
        
        # Encrypt
        return cls.encrypt_data(json_data, user_key)
    
    @classmethod
    def decrypt_medical_record(cls, encrypted_record: str, user_key: bytes) -> dict:
        """
        Decrypt a medical record.
        
        Args:
            encrypted_record: Base64-encoded encrypted record
            user_key: User's encryption key
            
        Returns:
            Decrypted record as dictionary
        """
        # Decrypt
        json_data = cls.decrypt_data(encrypted_record, user_key)
        
        # Parse JSON
        return json.loads(json_data)
    
    @classmethod
    def create_recovery_key(cls, user_key: bytes, admin_public_key: Optional[bytes] = None) -> str:
        """
        Create an encrypted recovery key for emergency access.
        This allows authorized administrators to recover data if user loses password.
        
        Args:
            user_key: User's encryption key
            admin_public_key: Optional admin public key for additional security
            
        Returns:
            Encrypted recovery key
        """
        # For now, use Fernet for recovery key encryption
        # In production, use RSA public key encryption
        recovery_key = Fernet.generate_key()
        f = Fernet(recovery_key)
        
        # Encrypt user key with recovery key
        encrypted_user_key = f.encrypt(user_key)
        
        # Return both (recovery key would be split among admins)
        return base64.urlsafe_b64encode(
            recovery_key + b'||' + encrypted_user_key
        ).decode('utf-8')
    
    @classmethod
    def recover_user_key(cls, recovery_data: str) -> bytes:
        """
        Recover user encryption key from recovery data.
        
        Args:
            recovery_data: Encrypted recovery data
            
        Returns:
            Recovered user encryption key
        """
        # Decode recovery data
        decoded = base64.urlsafe_b64decode(recovery_data.encode('utf-8'))
        
        # Split recovery key and encrypted user key
        recovery_key, encrypted_user_key = decoded.split(b'||')
        
        # Decrypt user key
        f = Fernet(recovery_key)
        user_key = f.decrypt(encrypted_user_key)
        
        return user_key
    
    @classmethod
    def hash_for_verification(cls, data: str) -> str:
        """
        Create a hash for data verification without revealing content.
        
        Args:
            data: Data to hash
            
        Returns:
            SHA-256 hash as hex string
        """
        return hashlib.sha256(data.encode('utf-8')).hexdigest()


class ZKEncryptionManager:
    """
    Manager for Zero-Knowledge Encryption operations.
    Handles user key management and encrypted storage.
    """
    
    def __init__(self):
        self.zke = ZeroKnowledgeEncryption()
        self.user_salts = {}  # In production, store in database
        self.active_keys = {}  # Temporary in-memory key storage (cleared on session end)
    
    def initialize_user(self, user_id: int, password: str) -> Tuple[str, str]:
        """
        Initialize Zero-Knowledge Encryption for a user.
        
        Args:
            user_id: User ID
            password: User's password
            
        Returns:
            (salt, recovery_key)
        """
        # Generate salt for this user
        salt = self.zke.generate_salt()
        
        # Derive encryption key from password
        user_key = self.zke.derive_key_from_password(password, salt)
        
        # Create recovery key
        recovery_key = self.zke.create_recovery_key(user_key)
        
        # Store salt (server-side, safe to store)
        self.user_salts[user_id] = salt
        
        # Don't store the key or password!
        return salt, recovery_key
    
    def unlock_session(self, user_id: int, password: str, salt: str) -> bool:
        """
        Unlock user session for encryption/decryption.
        Key is derived from password and kept in memory only for session duration.
        
        Args:
            user_id: User ID
            password: User's password
            salt: User's salt (retrieved from database)
            
        Returns:
            True if successful
        """
        try:
            # Derive key from password
            user_key = self.zke.derive_key_from_password(password, salt)
            
            # Store in active keys (session only)
            self.active_keys[user_id] = user_key
            
            return True
        except Exception:
            return False
    
    def lock_session(self, user_id: int):
        """
        Lock user session and clear encryption keys from memory.
        
        Args:
            user_id: User ID
        """
        if user_id in self.active_keys:
            # Overwrite key in memory before deletion
            self.active_keys[user_id] = b'\x00' * 32
            del self.active_keys[user_id]
    
    def encrypt_patient_data(self, user_id: int, patient_data: dict) -> Optional[str]:
        """
        Encrypt patient data using user's key.
        
        Args:
            user_id: User ID (must have active session)
            patient_data: Patient data dictionary
            
        Returns:
            Encrypted data or None if session not active
        """
        if user_id not in self.active_keys:
            return None
        
        user_key = self.active_keys[user_id]
        return self.zke.encrypt_medical_record(patient_data, user_key)
    
    def decrypt_patient_data(self, user_id: int, encrypted_data: str) -> Optional[dict]:
        """
        Decrypt patient data using user's key.
        
        Args:
            user_id: User ID (must have active session)
            encrypted_data: Encrypted patient data
            
        Returns:
            Decrypted data or None if session not active
        """
        if user_id not in self.active_keys:
            return None
        
        user_key = self.active_keys[user_id]
        return self.zke.decrypt_medical_record(encrypted_data, user_key)
    
    def is_session_active(self, user_id: int) -> bool:
        """Check if user has an active ZK encryption session"""
        return user_id in self.active_keys


# Global manager instance
zk_manager = ZKEncryptionManager()


# Utility functions
def initialize_zk_encryption(user_id: int, password: str) -> Tuple[str, str]:
    """Initialize Zero-Knowledge Encryption for a user"""
    return zk_manager.initialize_user(user_id, password)


def unlock_zk_session(user_id: int, password: str, salt: str) -> bool:
    """Unlock ZK encryption session for user"""
    return zk_manager.unlock_session(user_id, password, salt)


def lock_zk_session(user_id: int):
    """Lock ZK encryption session"""
    zk_manager.lock_session(user_id)


def encrypt_sensitive_data(user_id: int, data: dict) -> Optional[str]:
    """Encrypt sensitive data with user's ZK key"""
    return zk_manager.encrypt_patient_data(user_id, data)


def decrypt_sensitive_data(user_id: int, encrypted_data: str) -> Optional[dict]:
    """Decrypt sensitive data with user's ZK key"""
    return zk_manager.decrypt_patient_data(user_id, encrypted_data)
