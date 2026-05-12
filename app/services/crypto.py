import os, hashlib, base64
from cryptography.fernet import Fernet


def _fernet() -> Fernet:
    key = os.getenv("SECRET_KEY", "super-secret-random-string-12345")
    digest = hashlib.sha256(key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_pw(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_pw(enc: str) -> str:
    return _fernet().decrypt(enc.encode()).decode()


def encrypt_field(value: str | None) -> str | None:
    """Encrypt an arbitrary string field; None/empty passthrough."""
    if not value:
        return value
    return _fernet().encrypt(value.encode()).decode()


def decrypt_field(value: str | None) -> str | None:
    """Decrypt a field encrypted with encrypt_field; gracefully returns value as-is if not encrypted."""
    if not value:
        return value
    try:
        return _fernet().decrypt(value.encode()).decode()
    except Exception:
        return value  # plain-text fallback for unencrypted legacy rows
