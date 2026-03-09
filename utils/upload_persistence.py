"""utils/upload_persistence.py

Persistent file upload management with integrity tracking.

Ensures:
- Uploaded files are tracked in database (file_id, content_hash, encryption_key_id)
- Files survive redeploys (stored in persistent `uploads/` directory)
- Encryption keys are versioned for backward compatibility
- File integrity can be verified
- Orphaned files can be detected and recovered

Design:
- All uploads stored in `uploads/` directory (excluded from git, persisted by deployment)
- Each upload entry in database includes:
  - Original filename, size, content hash (SHA-256)
  - Encryption key ID used
  - Upload timestamp, user who uploaded
  - Associated entity type (profile_picture, prescription, etc)
  - Download count (for audit)
"""

import hashlib
import os
from datetime import datetime, timezone
from typing import Optional, Tuple
from abc import ABC, abstractmethod

# Import encryption and file storage functions
from utils.upload_encryption import (
    get_upload_encryption_key_bytes,
    encrypt_bytes,
    decrypt_bytes,
)


class FileUploadTracker(ABC):
    """Interface for tracking uploaded files in persistent storage."""

    @abstractmethod
    def get_file_record(self, file_id: str) -> Optional[dict]:
        """Retrieve file metadata from database."""
        pass

    @abstractmethod
    def create_file_record(self, 
                          rel_path: str,
                          user_id: int,
                          content_hash: str,
                          file_size: int,
                          original_filename: str,
                          category: str) -> bool:
        """Create database entry for uploaded file."""
        pass

    @abstractmethod
    def verify_file_integrity(self, file_id: str) -> Tuple[bool, Optional[str]]:
        """Verify file exists and hash matches database record."""
        pass

    @abstractmethod
    def mark_file_for_deletion(self, file_id: str) -> bool:
        """Mark file as deleted but keep metadata for audit trail."""
        pass


def compute_file_hash(file_bytes: bytes) -> str:
    """Compute SHA-256 hash of file content."""
    h = hashlib.sha256()
    h.update(file_bytes)
    return h.hexdigest()


def validate_persistent_upload_directory() -> Tuple[bool, Optional[str]]:
    """
    Verify uploads directory exists and is writable.
    
    Returns: (success, error_message)
    """
    uploads_dir = os.path.join(os.getcwd(), 'uploads')
    
    if not os.path.exists(uploads_dir):
        try:
            os.makedirs(uploads_dir, exist_ok=True)
        except Exception as e:
            return False, f"Failed to create uploads directory: {e}"
    
    if not os.access(uploads_dir, os.W_OK):
        return False, "uploads directory is not writable"
    
    # Verify subdirectories
    subdirs = ['profile_pictures', 'controlled_prescriptions']
    for subdir in subdirs:
        subdir_path = os.path.join(uploads_dir, subdir)
        if not os.path.exists(subdir_path):
            try:
                os.makedirs(subdir_path, exist_ok=True)
            except Exception as e:
                return False, f"Failed to create {subdir}: {e}"
    
    return True, None


def get_persistent_upload_path(rel_path: str) -> str:
    """
    Get absolute path for persistent upload file.
    
    Enforces that all uploads are in `uploads/` directory
    (excluded from git, persisted across deployments).
    """
    rel_normalized = os.path.normpath(rel_path).replace('\\', '/')
    
    # Prevent directory traversal
    if '..' in rel_normalized or rel_normalized.startswith('/'):
        raise ValueError(f"Invalid upload path: {rel_normalized}")
    
    uploads_dir = os.path.join(os.getcwd(), 'uploads')
    full_path = os.path.join(uploads_dir, rel_normalized)
    
    # Verify final path is under uploads/
    try:
        real_uploads = os.path.realpath(uploads_dir)
        real_path = os.path.realpath(full_path)
        if not real_path.startswith(real_uploads):
            raise ValueError(f"Path escape detected: {rel_normalized}")
    except (OSError, ValueError) as e:
        raise ValueError(f"Invalid path: {e}")
    
    return full_path


def backup_uploaded_file(rel_path: str, backup_dir: str = None) -> Tuple[bool, Optional[str]]:
    """
    Create backup copy of uploaded file.
    
    Returns: (success, error_message)
    
    Backups are stored in instance/file_backups/ by default.
    Useful for disaster recovery and audit trails.
    """
    try:
        if backup_dir is None:
            backup_dir = os.path.join(os.getcwd(), 'instance', 'file_backups')
        
        os.makedirs(backup_dir, exist_ok=True)
        
        source = get_persistent_upload_path(rel_path)
        if not os.path.isfile(source):
            return False, "Source file not found"
        
        # Create backup with timestamp
        filename = os.path.basename(rel_path)
        name, ext = os.path.splitext(filename)
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        backup_filename = f"{name}_{timestamp}{ext}"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        with open(source, 'rb') as src:
            with open(backup_path, 'wb') as dst:
                dst.write(src.read())
        
        return True, backup_path
    except Exception as e:
        return False, str(e)


def recover_uploaded_file(backup_path: str, target_rel_path: str) -> Tuple[bool, Optional[str]]:
    """
    Recover uploaded file from backup.
    
    Returns: (success, error_message)
    """
    try:
        if not os.path.isfile(backup_path):
            return False, "Backup file not found"
        
        target_path = get_persistent_upload_path(target_rel_path)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        
        with open(backup_path, 'rb') as src:
            with open(target_path, 'wb') as dst:
                dst.write(src.read())
        
        return True, target_path
    except Exception as e:
        return False, str(e)


def is_file_encrypted(file_path: str) -> bool:
    """Check if file at path is encrypted using our encryption format."""
    try:
        if not os.path.isfile(file_path):
            return False
        with open(file_path, 'rb') as f:
            header = f.read(10)
        return header.startswith(b'MMCUP1\n')  # Magic bytes from upload_encryption.py
    except Exception:
        return False


def get_upload_file_metadata(rel_path: str) -> Optional[dict]:
    """
    Retrieve metadata for uploaded file.
    
    Returns dict with:
    - path: relative path
    - size: file size in bytes
    - encrypted: whether file is encrypted
    - exists: whether file exists
    - hash: SHA-256 hash if file exists
    """
    try:
        file_path = get_persistent_upload_path(rel_path)
        
        if not os.path.isfile(file_path):
            return {
                'path': rel_path,
                'exists': False,
                'size': None,
                'encrypted': False,
                'hash': None,
            }
        
        size = os.path.getsize(file_path)
        encrypted = is_file_encrypted(file_path)
        
        with open(file_path, 'rb') as f:
            content = f.read()
        file_hash = compute_file_hash(content)
        
        return {
            'path': rel_path,
            'exists': True,
            'size': size,
            'encrypted': encrypted,
            'hash': file_hash,
            'mtime': datetime.fromtimestamp(os.path.getmtime(file_path), tz=timezone.utc),
        }
    except Exception as e:
        return {
            'path': rel_path,
            'exists': False,
            'error': str(e),
        }


class PersistenceStatus:
    """Status check for upload persistence infrastructure."""
    
    @staticmethod
    def check_all() -> dict:
        """Run all persistence checks."""
        status = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'uploads_directory': None,
            'profile_pictures': [],
            'prescriptions': [],
            'backup_directory': None,
        }
        
        # Check uploads directory
        valid, error = validate_persistent_upload_directory()
        status['uploads_directory'] = {
            'valid': valid,
            'error': error,
            'path': os.path.join(os.getcwd(), 'uploads'),
        }
        
        # Check existing files
        try:
            uploads_dir = os.path.join(os.getcwd(), 'uploads')
            
            # Profile pictures
            profile_pics_dir = os.path.join(uploads_dir, 'profile_pictures')
            if os.path.isdir(profile_pics_dir):
                for fname in os.listdir(profile_pics_dir):
                    rel = f"profile_pictures/{fname}"
                    meta = get_upload_file_metadata(
                        os.path.relpath(
                            os.path.join(profile_pics_dir, fname),
                            uploads_dir
                        )
                    )
                    status['profile_pictures'].append(meta)
            
            # Backup directory
            backup_dir = os.path.join(os.getcwd(), 'instance', 'file_backups')
            if os.path.isdir(backup_dir):
                backup_files = [f for f in os.listdir(backup_dir) if os.path.isfile(os.path.join(backup_dir, f))]
                status['backup_directory'] = {
                    'path': backup_dir,
                    'file_count': len(backup_files),
                    'files': backup_files[:10],  # First 10
                }
        except Exception as e:
            status['error'] = str(e)
        
        return status
