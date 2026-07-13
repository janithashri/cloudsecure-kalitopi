from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.db import repositories as repo
from app.models.orm import AuthUser, Tenant, UserProfile


def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Token "):
        return auth[6:].strip()
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def get_current_user(request: Request, db: Session = Depends(get_db)) -> AuthUser:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    user = repo.get_user_by_token(db, token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return user

def get_user_profile(
    user: AuthUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserProfile:
    profile = repo.get_user_profile(db, user.id)
    if not profile:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tenant profile")
    return profile

def get_current_tenant(
    user: UserProfile = Depends(get_user_profile),
    db: Session = Depends(get_db),
) -> Tenant:
    tenant=repo.get_tenant(db,user.tenant_id)
    if not tenant:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant not found")
    return tenant



