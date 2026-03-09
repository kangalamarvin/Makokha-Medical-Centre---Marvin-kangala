"""utils/upload_management.py

High-level upload file management with database tracking and integrity verification.

Provides:
- Register uploads to database with metadata and hashing
- Verify file integrity against stored hash
- Track file access
- Detect and recover orphaned files
- Automatic backup on upload
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple, List

from utils.upload_persistence import (
    compute_file_hash,
    get_persistent_upload_path,
    backup_uploaded_file,
)

logger = logging.getLogger(__name__)


class UploadManager:
    """Manage uploaded files with database tracking and integrity verification."""
    
    def __init__(self, db_session):
        """Initialize with database session."""
        self.db = db_session
        self.UploadedFile = None  # Will be set after app context
    
    def set_model(self, model):
        """Set the UploadedFile model (called after app initialization)."""
        self.UploadedFile = model
    
    def register_upload(self,
                        rel_path: str,
                        original_filename: str,
                        file_bytes: bytes,
                        category: str,
                        uploader_id: int = None,
                        user_id: int = None,
                        mime_type: str = None,
                        create_backup: bool = True) -> Tuple[bool, Optional[str], Optional[dict]]:
        """
        Register an uploaded file to database.
        
        Args:
            rel_path: Relative path within uploads/ (e.g., "profile_pictures/user123.jpg")
            original_filename: Original filename as uploaded
            file_bytes: File content as bytes
            category: Category of upload ("profile_picture", "prescription", etc)
            uploader_id: ID of user who uploaded (optional)
            user_id: ID of user associated with file (optional, for profile pics)
            mime_type: MIME type of file (optional, will be guessed)
            create_backup: Whether to create backup copy
        
        Returns: (success, error_message, metadata)
        """
        try:
            if not self.UploadedFile:
                return False, "UploadedFile model not initialized", None
            
            # Validate inputs
            if not rel_path or not original_filename or file_bytes is None:
                return False, "Missing required parameters", None
            
            if not isinstance(file_bytes, (bytes, bytearray)):
                return False, "file_bytes must be bytes", None
            
            # Compute hash for integrity verification
            content_hash = compute_file_hash(bytes(file_bytes))
            file_size = len(file_bytes)
            
            # Check if file already tracked
            existing = self.db.query(self.UploadedFile).filter_by(
                relative_path=rel_path
            ).first()
            
            if existing:
                # Update existing record
                existing.original_filename = original_filename
                existing.file_size = file_size
                existing.content_hash = content_hash
                existing.mime_type = mime_type or existing.mime_type
                existing.uploader_id = uploader_id or existing.uploader_id
                existing.user_id = user_id or existing.user_id
                existing.deleted_at = None  # Restore if was previously deleted
                self.db.commit()
                
                logger.info(f"Updated upload record: {rel_path} (size={file_size}, hash={content_hash[:16]}...)")
            else:
                # Create new record
                record = self.UploadedFile(
                    relative_path=rel_path,
                    original_filename=original_filename,
                    file_size=file_size,
                    content_hash=content_hash,
                    mime_type=mime_type,
                    category=category,
                    is_encrypted=True,  # Assuming encryption is used
                    uploader_id=uploader_id,
                    user_id=user_id,
                    created_at=datetime.now(timezone.utc),
                )
                self.db.add(record)
                self.db.commit()
                
                logger.info(f"Registered upload: {rel_path} (size={file_size}, hash={content_hash[:16]}...)")
            
            # Create backup if requested
            if create_backup:
                try:
                    success, backup_path = backup_uploaded_file(rel_path)
                    if success:
                        logger.info(f"Backup created: {backup_path}")
                    else:
                        logger.warning(f"Backup failed for {rel_path}: {backup_path}")
                except Exception as e:
                    logger.warning(f"Could not backup {rel_path}: {e}")
            
            metadata = {
                'relative_path': rel_path,
                'file_size': file_size,
                'content_hash': content_hash,
                'category': category,
                'mime_type': mime_type,
            }
            
            return True, None, metadata
        
        except Exception as e:
            logger.error(f"Failed to register upload {rel_path}: {e}", exc_info=True)
            return False, str(e), None
    
    def verify_file_integrity(self, rel_path: str) -> Tuple[bool, Optional[str]]:
        """
        Verify file exists and hash matches database record.
        
        Returns: (valid, error_message)
        """
        try:
            record = self.db.query(self.UploadedFile).filter_by(
                relative_path=rel_path,
                deleted_at=None
            ).first()
            
            if not record:
                return False, "File not found in database"
            
            # Check file exists
            file_path = get_persistent_upload_path(rel_path)
            if not os.path.isfile(file_path):
                logger.error(f"File missing on disk: {rel_path}")
                return False, "File missing from filesystem"
            
            # Verify hash
            with open(file_path, 'rb') as f:
                content = f.read()
            actual_hash = compute_file_hash(content)
            
            if actual_hash != record.content_hash:
                logger.error(f"Hash mismatch for {rel_path}: {actual_hash} != {record.content_hash}")
                return False, "File content hash mismatch (file may be corrupted)"
            
            # Update verification timestamp
            record.last_verified_at = datetime.now(timezone.utc)
            self.db.commit()
            
            logger.info(f"File integrity verified: {rel_path}")
            return True, None
        
        except Exception as e:
            logger.error(f"Integrity verification error for {rel_path}: {e}", exc_info=True)
            return False, str(e)
    
    def track_access(self, rel_path: str) -> None:
        """Record file access."""
        try:
            record = self.db.query(self.UploadedFile).filter_by(
                relative_path=rel_path,
                deleted_at=None
            ).first()
            
            if record:
                record.increment_access()
                self.db.commit()
        except Exception as e:
            logger.warning(f"Failed to track access for {rel_path}: {e}")
    
    def mark_deleted(self, rel_path: str) -> Tuple[bool, Optional[str]]:
        """Soft-delete file (keep metadata for audit trail)."""
        try:
            record = self.db.query(self.UploadedFile).filter_by(
                relative_path=rel_path
            ).first()
            
            if not record:
                return False, "File not found in database"
            
            record.soft_delete()
            self.db.commit()
            
            logger.info(f"Marked for deletion: {rel_path}")
            return True, None
        
        except Exception as e:
            logger.error(f"Failed to delete record for {rel_path}: {e}")
            return False, str(e)
    
    def find_orphaned_files(self) -> List[str]:
        """
        Find files on disk not tracked in database.
        
        Returns: List of relative paths to orphaned files.
        """
        orphaned = []
        try:
            uploads_dir = os.path.join(os.getcwd(), 'uploads')
            if not os.path.isdir(uploads_dir):
                return orphaned
            
            # Get all database records
            records = self.db.query(self.UploadedFile).all()
            tracked_paths = {r.relative_path for r in records}
            
            # Walk filesystem
            for root, dirs, files in os.walk(uploads_dir):
                for filename in files:
                    full_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(full_path, uploads_dir).replace('\\', '/')
                    
                    if rel_path not in tracked_paths:
                        orphaned.append(rel_path)
            
            if orphaned:
                logger.info(f"Found {len(orphaned)} orphaned files")
            
            return orphaned
        
        except Exception as e:
            logger.error(f"Error scanning for orphaned files: {e}")
            return orphaned
    
    def get_category_statistics(self) -> dict:
        """Get statistics on uploaded files by category."""
        try:
            stats = {}
            
            categories = self.db.query(
                self.UploadedFile.category,
                self.UploadedFile.id.__class__.count(self.UploadedFile.id),
            ).filter(
                self.UploadedFile.deleted_at == None
            ).group_by(
                self.UploadedFile.category
            ).all()
            
            for category, count in categories:
                stats[category] = {
                    'count': count,
                    'total_size': sum(
                        r.file_size for r in self.db.query(self.UploadedFile).filter(
                            self.UploadedFile.category == category,
                            self.UploadedFile.deleted_at == None
                        ).all()
                    )
                }
            
            return stats
        
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}


# Global instance (initialized in app factory)
upload_manager = UploadManager(None)
