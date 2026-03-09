"""Encrypt existing private uploads in-place.

This is a one-time maintenance script to ensure historical files under the
private `uploads/` directory are encrypted at rest.

Usage (Windows PowerShell):
  C:/Users/makok/Desktop/Makokha-Medical-Centre/venv/Scripts/python.exe scripts/encrypt_existing_uploads.py

Key:
- Provide UPLOAD_ENCRYPTION_KEY (base64url, 32 bytes) in the environment for
  stable key management, OR let the app create `instance/upload_encryption.key`.

Safety:
- Skips files that already look encrypted.
- Only touches files under `uploads/`.
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from utils.upload_encryption import encrypt_file_inplace


def main() -> int:
    root = os.path.join(os.getcwd(), "uploads")
    if not os.path.isdir(root):
        print("No uploads/ directory found; nothing to do")
        return 0

    total = 0
    changed = 0
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            total += 1
            path = os.path.join(dirpath, name)
            try:
                if encrypt_file_inplace(path):
                    changed += 1
                    print(f"encrypted: {os.path.relpath(path, os.getcwd())}")
            except Exception as e:
                print(f"failed: {os.path.relpath(path, os.getcwd())}: {e}")

    print(f"done: {changed}/{total} files encrypted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
