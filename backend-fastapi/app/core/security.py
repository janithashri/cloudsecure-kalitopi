import secrets

from passlib.hash import django_pbkdf2_sha256


def hash_password(password: str) -> str:
    return django_pbkdf2_sha256.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return django_pbkdf2_sha256.verify(plain, hashed)
    except Exception:
        return False


def generate_token_key() -> str:
    return secrets.token_hex(20)


