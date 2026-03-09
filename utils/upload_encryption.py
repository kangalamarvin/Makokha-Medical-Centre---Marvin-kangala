"""utils/upload_encryption.py

Encrypt/decrypt user-uploaded files at rest.

Scope:
- Only for user uploads stored under the app's private `uploads/` directory.
- Static app assets (e.g., `/static/...` icons) are not encrypted.

Design goals:
- Backward compatible: if a file is not encrypted, it is served as-is.
- Safe key handling: key comes from env UPLOAD_ENCRYPTION_KEY or is persisted
  to instance/upload_encryption.key on first use.
- Atomic writes: encrypt in a temp file then replace.

File format (v1):
- MAGIC + nonce(12 bytes) + AESGCM(ciphertext||tag)

Note: This uses whole-file encryption; the app enforces upload size limits.
"""

from __future__ import annotations

import base64
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_MAGIC = b"MMCUP1\n"
_NONCE_LEN = 12
_KEY_LEN = 32


def _b64url_decode(s: str) -> bytes:
    s = (s or "").strip()
    if not s:
        raise ValueError("empty")
    # Add padding if missing.
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _key_from_env(var_name: str) -> Optional[bytes]:
    raw = os.getenv(var_name)
    if not raw:
        return None
    try:
        key = _b64url_decode(raw)
    except Exception:
        return None
    if len(key) != _KEY_LEN:
        return None
    return key


def _instance_key_path() -> str:
    instance_dir = os.path.join(os.getcwd(), "instance")
    os.makedirs(instance_dir, exist_ok=True)
    return os.path.join(instance_dir, "upload_encryption.key")


def _read_instance_key() -> Optional[bytes]:
    key_path = _instance_key_path()
    if not os.path.exists(key_path):
        return None
    try:
        with open(key_path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        key = _b64url_decode(raw)
        if len(key) != _KEY_LEN:
            return None
        return key
    except Exception:
        return None


def _write_instance_key(key: bytes) -> None:
    if not key or len(key) != _KEY_LEN:
        raise ValueError("Invalid upload encryption key")
    key_path = _instance_key_path()
    with open(key_path, "w", encoding="utf-8") as f:
        f.write(_b64url_encode(key))


def _collect_candidate_keys() -> list[bytes]:
    keys: list[bytes] = []
    for env_name in ("UPLOAD_ENCRYPTION_KEY", "FERNET_KEY", "BACKUP_ENCRYPTION_KEY"):
        k = _key_from_env(env_name)
        if k and k not in keys:
            keys.append(k)

    inst = _read_instance_key()
    if inst and inst not in keys:
        keys.append(inst)
    return keys


def get_upload_encryption_key_bytes() -> bytes:
    """Return the AES-GCM key bytes.

    Key priority:
    1) UPLOAD_ENCRYPTION_KEY
    2) FERNET_KEY
    3) BACKUP_ENCRYPTION_KEY
    4) instance/upload_encryption.key (legacy/dev fallback)
    """

    candidates = _collect_candidate_keys()
    if candidates:
        return candidates[0]

    # Dev fallback only when no stable environment key is set.
    key = os.urandom(_KEY_LEN)
    _write_instance_key(key)
    return key


def is_encrypted_blob(blob: bytes) -> bool:
    return isinstance(blob, (bytes, bytearray)) and blob.startswith(_MAGIC) and len(blob) > len(_MAGIC) + _NONCE_LEN


def encrypt_bytes(plaintext: bytes, *, key: Optional[bytes] = None) -> bytes:
    if plaintext is None:
        raise ValueError("plaintext is None")
    if is_encrypted_blob(plaintext):
        return bytes(plaintext)

    key_bytes = key or get_upload_encryption_key_bytes()
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(_NONCE_LEN)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return _MAGIC + nonce + ct


def decrypt_bytes(blob: bytes, *, key: Optional[bytes] = None) -> bytes:
    if blob is None:
        raise ValueError("blob is None")
    if not is_encrypted_blob(blob):
        return bytes(blob)

    nonce_start = len(_MAGIC)
    nonce_end = nonce_start + _NONCE_LEN
    nonce = blob[nonce_start:nonce_end]
    ct = blob[nonce_end:]

    keys_to_try = []
    if key is not None:
        keys_to_try.append(key)
    else:
        keys_to_try.extend(_collect_candidate_keys())
        if not keys_to_try:
            keys_to_try.append(get_upload_encryption_key_bytes())

    last_error: Optional[Exception] = None
    for key_bytes in keys_to_try:
        try:
            aesgcm = AESGCM(key_bytes)
            return aesgcm.decrypt(nonce, ct, None)
        except Exception as exc:
            last_error = exc
            continue
    if last_error:
        raise last_error
    raise ValueError("No upload encryption keys available")


def is_encrypted_file(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(len(_MAGIC))
        return head == _MAGIC
    except Exception:
        return False


def encrypt_file_inplace(path: str) -> bool:
    """Encrypt a file in-place. Returns True if encryption happened."""

    if not path:
        return False

    try:
        if is_encrypted_file(path):
            return False

        with open(path, "rb") as f:
            plaintext = f.read()

        encrypted = encrypt_bytes(plaintext)
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(encrypted)
        os.replace(tmp, path)
        return True
    except Exception:
        # Best-effort; leave original file untouched if anything goes wrong.
        try:
            tmp = path + ".tmp"
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return False


def decrypt_file_to_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        blob = f.read()
    return decrypt_bytes(blob)
