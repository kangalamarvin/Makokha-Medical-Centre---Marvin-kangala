"""
End-to-End Message Encryption Module
Uses Fernet (symmetric encryption) for message content
"""
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


class MessageEncryption:
    """Handle end-to-end encryption for messages"""
    
    def __init__(self, encryption_key=None):
        """
        Initialize encryption handler
        
        Args:
            encryption_key: Optional base64-encoded Fernet key. 
                          If not provided, uses MESSAGE_ENCRYPTION_KEY from env
        """
        if encryption_key:
            self.key = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
        else:
            # Get from environment variable
            env_key = os.getenv('MESSAGE_ENCRYPTION_KEY')
            if env_key:
                self.key = env_key.encode()
            else:
                # Generate new key (not recommended for production - store in env)
                self.key = Fernet.generate_key()
        
        self.cipher = Fernet(self.key)
    
    def encrypt_message(self, plaintext):
        """
        Encrypt a message
        
        Args:
            plaintext: String message to encrypt
            
        Returns:
            Base64-encoded encrypted message
        """
        if not plaintext:
            return None
        
        try:
            encrypted = self.cipher.encrypt(plaintext.encode('utf-8'))
            return encrypted.decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            return None
    
    def decrypt_message(self, ciphertext):
        """
        Decrypt a message
        
        Args:
            ciphertext: Base64-encoded encrypted message
            
        Returns:
            Decrypted plaintext message
        """
        if not ciphertext:
            return None
        
        try:
            decrypted = self.cipher.decrypt(ciphertext.encode('utf-8'))
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    @staticmethod
    def generate_key():
        """Generate a new Fernet key"""
        return Fernet.generate_key().decode('utf-8')
    
    @staticmethod
    def derive_key_from_password(password, salt=None):
        """
        Derive an encryption key from a password
        
        Args:
            password: User password
            salt: Optional salt bytes. If not provided, generates new salt
            
        Returns:
            (key, salt) tuple
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode('utf-8'), base64.b64encode(salt).decode('utf-8')


# Utility functions for easy use
def encrypt_message_content(content, key=None):
    """
    Quick function to encrypt message content
    
    Args:
        content: Message content to encrypt
        key: Optional encryption key
        
    Returns:
        Encrypted content or original if encryption fails/disabled
    """
    try:
        encryptor = MessageEncryption(key)
        encrypted = encryptor.encrypt_message(content)
        return encrypted if encrypted else content
    except Exception:
        # If encryption fails, return original content
        return content


def decrypt_message_content(encrypted_content, key=None):
    """
    Quick function to decrypt message content
    
    Args:
        encrypted_content: Encrypted message content
        key: Optional encryption key
        
    Returns:
        Decrypted content or original if decryption fails/disabled
    """
    try:
        decryptor = MessageEncryption(key)
        decrypted = decryptor.decrypt_message(encrypted_content)
        return decrypted if decrypted else encrypted_content
    except Exception:
        # If decryption fails, return original content
        return encrypted_content


# Example usage:
# 
# # Generate key (do this once, store in .env)
# from utils.message_encryption import MessageEncryption
# key = MessageEncryption.generate_key()
# print(f"Add to .env: MESSAGE_ENCRYPTION_KEY={key}")
#
# # Encrypt a message
# encrypted = encrypt_message_content("Hello, this is secret!")
#
# # Decrypt a message
# decrypted = decrypt_message_content(encrypted)
