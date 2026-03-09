#!/usr/bin/env python3
"""scripts/manage_uploads.py

Management script for upload persistence system.

Usage:
    python manage_uploads.py init-persistence
        Initialize persistence system after deployment
    
    python manage_uploads.py register-existing
        Register already-uploaded files (not in database) to database
    
    python manage_uploads.py verify-integrity
        Verify all uploaded files match stored hashes
    
    python manage_uploads.py find-orphaned
        Find files on disk not tracked in database
    
    python manage_uploads.py status
        Show upload persistence status
    
    python manage_uploads.py backup-all
        Create backups of all uploaded files
"""

import sys
import os
import argparse
from pathlib import Path

# Add parent directory to path to import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, UploadedFile
from utils.upload_persistence import (
    compute_file_hash,
    get_persistent_upload_path,
    validate_persistent_upload_directory,
    backup_uploaded_file,
    PersistenceStatus,
)
from datetime import datetime, timezone


def init_persistence():
    """Initialize persistence system after deployment."""
    print("✓ Initializing upload persistence system...")
    
    with app.app_context():
        # Check/create uploads directory
        valid, error = validate_persistent_upload_directory()
        if not valid:
            print(f"✗ Error: {error}")
            return False
        
        print("✓ Uploads directory valid and writable")
        print(f"  Location: {os.path.join(os.getcwd(), 'uploads')}")
        
        # Check database connection
        try:
            result = db.session.execute("SELECT 1").fetchone()
            print("✓ Database connection OK")
        except Exception as e:
            print(f"✗ Database connection failed: {e}")
            return False
        
        # Check if UploadedFile table exists
        try:
            db.session.query(UploadedFile).limit(1).all()
            print("✓ UploadedFile table exists")
        except Exception as e:
            print(f"✗ UploadedFile table not found: {e}")
            print("  Run: flask db upgrade")
            return False
        
        print("\n✓ Persistence system initialized successfully!")
        return True


def register_existing():
    """Register existing files to database."""
    print("✓ Scanning for unregistered uploads...")
    
    with app.app_context():
        uploads_dir = os.path.join(os.getcwd(), 'uploads')
        registered = 0
        skipped = 0
        
        if not os.path.isdir(uploads_dir):
            print("✗ Uploads directory not found")
            return False
        
        # Get already-tracked files
        existing = {f.relative_path for f in db.session.query(UploadedFile).all()}
        
        # Walk filesystem
        for root, dirs, files in os.walk(uploads_dir):
            for filename in files:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, uploads_dir).replace('\\', '/')
                
                if rel_path in existing:
                    skipped += 1
                    continue
                
                try:
                    # Read file
                    with open(full_path, 'rb') as f:
                        content = f.read()
                    
                    content_hash = compute_file_hash(content)
                    file_size = len(content)
                    
                    # Determine category from path
                    if 'profile_pictures' in rel_path:
                        category = 'profile_picture'
                    elif 'controlled_prescriptions' in rel_path:
                        category = 'prescription'
                    else:
                        category = 'other'
                    
                    # Create database entry
                    record = UploadedFile(
                        relative_path=rel_path,
                        original_filename=filename,
                        file_size=file_size,
                        content_hash=content_hash,
                        category=category,
                        is_encrypted=content.startswith(b'MMCUP1\n'),  # Check for encryption magic
                        created_at=datetime.fromtimestamp(os.path.getmtime(full_path), tz=timezone.utc),
                    )
                    
                    db.session.add(record)
                    registered += 1
                    
                    if registered % 10 == 0:
                        print(f"  Registered {registered} files...")
                
                except Exception as e:
                    print(f"✗ Error registering {rel_path}: {e}")
        
        db.session.commit()
        
        print(f"\n✓ Registration complete:")
        print(f"  Registered: {registered} new files")
        print(f"  Skipped: {skipped} already tracked")
        return True


def verify_integrity():
    """Verify all files match stored hashes."""
    print("✓ Verifying file integrity...")
    
    with app.app_context():
        files = db.session.query(UploadedFile).filter(UploadedFile.deleted_at == None).all()
        
        verified = 0
        failed = 0
        missing = 0
        
        print(f"  Total files to verify: {len(files)}\n")
        
        for i, record in enumerate(files):
            try:
                file_path = get_persistent_upload_path(record.relative_path)
                
                if not os.path.isfile(file_path):
                    print(f"✗ [{i+1}/{len(files)}] MISSING: {record.relative_path}")
                    missing += 1
                    continue
                
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                actual_hash = compute_file_hash(content)
                
                if actual_hash == record.content_hash:
                    verified += 1
                    if (verified + failed + missing) % 10 == 0:
                        print(f"  [{i+1}/{len(files)}] Verified {verified} files...")
                else:
                    print(f"✗ [{i+1}/{len(files)}] HASH MISMATCH: {record.relative_path}")
                    print(f"    Expected: {record.content_hash}")
                    print(f"    Actual:   {actual_hash}")
                    failed += 1
            
            except Exception as e:
                print(f"✗ [{i+1}/{len(files)}] ERROR: {record.relative_path}: {e}")
                failed += 1
        
        # Update verification timestamps
        for record in files:
            if not os.path.isfile(get_persistent_upload_path(record.relative_path)):
                continue
            try:
                with open(get_persistent_upload_path(record.relative_path), 'rb') as f:
                    content = f.read()
                if compute_file_hash(content) == record.content_hash:
                    record.last_verified_at = datetime.now(timezone.utc)
            except:
                pass
        
        db.session.commit()
        
        print(f"\n✓ Verification complete:")
        print(f"  Verified: {verified} files ✓")
        print(f"  Failed: {failed} files ✗")
        print(f"  Missing: {missing} files ⚠")
        
        return failed == 0 and missing == 0


def find_orphaned():
    """Find files not tracked in database."""
    print("✓ Scanning for orphaned files...")
    
    with app.app_context():
        uploads_dir = os.path.join(os.getcwd(), 'uploads')
        orphaned = []
        
        if not os.path.isdir(uploads_dir):
            print("✗ Uploads directory not found")
            return False
        
        # Get tracked files
        tracked = {f.relative_path for f in db.session.query(UploadedFile).all()}
        
        # Walk filesystem
        for root, dirs, files in os.walk(uploads_dir):
            for filename in files:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, uploads_dir).replace('\\', '/')
                
                if rel_path not in tracked:
                    try:
                        size = os.path.getsize(full_path)
                        mtime = datetime.fromtimestamp(os.path.getmtime(full_path), tz=timezone.utc)
                        orphaned.append((rel_path, size, mtime))
                    except Exception as e:
                        print(f"✗ Error scanning {rel_path}: {e}")
        
        if orphaned:
            print(f"\n✓ Found {len(orphaned)} orphaned files:\n")
            for path, size, mtime in orphaned:
                print(f"  {path}")
                print(f"    Size: {size} bytes")
                print(f"    Modified: {mtime.isoformat()}\n")
        else:
            print("\n✓ No orphaned files found - all files are tracked!")
        
        return True


def show_status():
    """Show upload persistence status."""
    print("=" * 60)
    print("UPLOAD PERSISTENCE STATUS")
    print("=" * 60)
    
    with app.app_context():
        # Get status
        status = PersistenceStatus.check_all()
        
        # Directory status
        uploads_status = status.get('uploads_directory', {})
        print(f"\n📁 Uploads Directory:")
        print(f"   Path: {uploads_status.get('path')}")
        print(f"   Status: {'✓ Valid' if uploads_status.get('valid') else '✗ Invalid'}")
        if uploads_status.get('error'):
            print(f"   Error: {uploads_status.get('error')}")
        
        # File statistics
        total_files = db.session.execute("SELECT COUNT(*) FROM uploaded_files WHERE deleted_at IS NULL").scalar()
        total_size = db.session.execute("SELECT SUM(file_size) FROM uploaded_files WHERE deleted_at IS NULL").scalar() or 0
        encrypted = db.session.execute("SELECT COUNT(*) FROM uploaded_files WHERE is_encrypted=true AND deleted_at IS NULL").scalar()
        
        print(f"\n📊 File Statistics:")
        print(f"   Total files: {total_files}")
        print(f"   Total size: {total_size / (1024*1024):.2f} MB")
        print(f"   Encrypted: {encrypted}/{total_files}")
        
        # Categories
        categories = db.session.execute(
            "SELECT category, COUNT(*), SUM(file_size) FROM uploaded_files WHERE deleted_at IS NULL GROUP BY category"
        ).fetchall()
        
        if categories:
            print(f"\n📂 By Category:")
            for cat, count, size in categories:
                print(f"   {cat}: {count} files ({size / 1024:.1f} KB)")
        
        # Backups
        backup_dir = status.get('backup_directory', {})
        if backup_dir:
            print(f"\n💾 Backups:")
            print(f"   Location: {backup_dir.get('path')}")
            print(f"   Files: {backup_dir.get('file_count', 0)}")
        
        print("\n" + "=" * 60)
        return True


def backup_all():
    """Create backups of all uploaded files."""
    print("✓ Creating backups of all uploaded files...")
    
    with app.app_context():
        files = db.session.query(UploadedFile).filter(UploadedFile.deleted_at == None).all()
        
        backed_up = 0
        failed = 0
        
        print(f"  Total files to backup: {len(files)}\n")
        
        for i, record in enumerate(files):
            try:
                success, result = backup_uploaded_file(record.relative_path)
                
                if success:
                    backed_up += 1
                    if backed_up % 10 == 0:
                        print(f"  [{i+1}/{len(files)}] Backed up {backed_up} files...")
                else:
                    print(f"✗ [{i+1}/{len(files)}] FAILED: {record.relative_path}: {result}")
                    failed += 1
            
            except Exception as e:
                print(f"✗ [{i+1}/{len(files)}] ERROR: {record.relative_path}: {e}")
                failed += 1
        
        print(f"\n✓ Backup complete:")
        print(f"  Backed up: {backed_up} files")
        print(f"  Failed: {failed} files")
        return failed == 0


def main():
    parser = argparse.ArgumentParser(
        description='Upload persistence management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    subparsers.add_parser('init-persistence', help='Initialize persistence system')
    subparsers.add_parser('register-existing', help='Register existing files')
    subparsers.add_parser('verify-integrity', help='Verify file integrity')
    subparsers.add_parser('find-orphaned', help='Find untracked files')
    subparsers.add_parser('status', help='Show status')
    subparsers.add_parser('backup-all', help='Backup all files')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    if args.command == 'init-persistence':
        return 0 if init_persistence() else 1
    elif args.command == 'register-existing':
        return 0 if register_existing() else 1
    elif args.command == 'verify-integrity':
        return 0 if verify_integrity() else 1
    elif args.command == 'find-orphaned':
        return 0 if find_orphaned() else 1
    elif args.command == 'status':
        return 0 if show_status() else 1
    elif args.command == 'backup-all':
        return 0 if backup_all() else 1
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
