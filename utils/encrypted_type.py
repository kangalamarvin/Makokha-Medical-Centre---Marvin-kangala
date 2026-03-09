import json
from sqlalchemy.types import TypeDecorator, LargeBinary, Text
from .encryption import EncryptionUtils
from flask import current_app

class EncryptedType(TypeDecorator):
    """
    Custom SQLAlchemy type for transparent encryption.
    Encrypts data when writing to the database and decrypts when reading.
    """
    # Default impl; overridden per-dialect via load_dialect_impl.
    impl = LargeBinary
    cache_ok = True

    def __init__(self, *args, encrypt_non_sqlite: bool = True, **kwargs):
        # encrypt_non_sqlite=True enables field-level encryption on PostgreSQL and
        # other DBs where the column is typically TEXT. For legacy schemas that
        # rely on plaintext for uniqueness/indexing (e.g., username/email), callers
        # can opt out per-column.
        self.encrypt_non_sqlite = bool(encrypt_non_sqlite)
        super(EncryptedType, self).__init__(*args, **kwargs)

    def load_dialect_impl(self, dialect):
        """Use BYTEA/BLOB on SQLite, but TEXT elsewhere.

        This keeps older SQLite deployments encrypted-at-rest while remaining
        compatible with existing PostgreSQL schemas that store plaintext
        in VARCHAR/TEXT columns.
        """
        if getattr(dialect, 'name', None) == 'sqlite':
            return dialect.type_descriptor(LargeBinary())
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):
        """
        Encrypt data before sending to the database.
        Handles various data types by serializing to JSON.
        """
        if value is None:
            return None

        try:
            # Serialize non-string data to JSON
            if not isinstance(value, str):
                serialized_value = json.dumps(value, default=str)  # Use default=str for dates
            else:
                serialized_value = value

            is_sqlite = getattr(dialect, 'name', None) == 'sqlite'

            # Allow per-column opt-out for non-sqlite DBs (legacy searchable/unique fields).
            if not is_sqlite and not self.encrypt_non_sqlite:
                return serialized_value

            # Avoid double-encrypting if a caller passes an existing token.
            if isinstance(serialized_value, str) and serialized_value.startswith('gAAAA'):
                encrypted_value = serialized_value
            else:
                encrypted_value = EncryptionUtils.encrypt_data(serialized_value)

            if is_sqlite:
                return encrypted_value.encode('utf-8')  # Store as bytes
            return encrypted_value  # Store as TEXT on non-sqlite
        except Exception as e:
            try:
                current_app.logger.error(f"Encryption failed for value: {str(e)}")
            except Exception:
                pass
            return None

    def process_result_value(self, value, dialect):
        """
        Decrypt data when reading from the database.
        Deserializes JSON for non-string data.
        """
        if value is None:
            return None

        try:
            # Normalize to string for downstream logic
            if isinstance(value, (bytes, bytearray, memoryview)):
                raw = bytes(value).decode('utf-8', errors='ignore')
            else:
                raw = str(value)

            if getattr(dialect, 'name', None) == 'sqlite':
                decrypted_value = EncryptionUtils.decrypt_data(raw)
                try:
                    return json.loads(decrypted_value)
                except (json.JSONDecodeError, TypeError):
                    return decrypted_value

            # Non-sqlite DBs may store plaintext (existing schemas) OR encrypted tokens.
            looks_like_fernet = raw.startswith('gAAAA')
            if looks_like_fernet:
                dec = EncryptionUtils.decrypt_data(raw)
                # If decryption failed, keep the raw value rather than replacing with an error string.
                if isinstance(dec, str) and dec.startswith('[Decryption Error'):
                    return raw
                try:
                    return json.loads(dec)
                except (json.JSONDecodeError, TypeError):
                    return dec

            # Plaintext path
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                return raw
        except Exception as e:
            try:
                current_app.logger.error(f"Decryption failed for value: {str(e)}")
            except Exception:
                pass
            return value

    @property
    def python_type(self):
        # This hints to SQLAlchemy about the type of data to expect
        return object
