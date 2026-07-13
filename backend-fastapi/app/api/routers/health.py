from fastapi import APIRouter
from sqlalchemy import text

from app.core.config import get_settings
from app.core.database import SessionLocal

router = APIRouter(tags=["health"])


@router.get("/health/")
def health():
    return {"status": "ok", "message": "Server is responding (no DB check)"}


@router.get("/debug-db/")
def debug_db():
    settings = get_settings()
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        return {"status": "ok", "db": "connected", "host": settings.postgres_host}
    except Exception as e:
        return {"status": "error", "db": str(e)}
