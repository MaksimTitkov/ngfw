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
