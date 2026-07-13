from app.core.database import SessionLocal
from app.db import repositories as repo


def load_hashes(account_id: str) -> dict:
    with SessionLocal() as db:
        return repo.load_hashes(db, account_id)


def save_hashes(account_id: str, hashes: dict):
    with SessionLocal() as db:
        repo.save_hashes(db, account_id, hashes)
