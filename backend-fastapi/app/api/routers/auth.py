from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.security import hash_password, verify_password
from app.db import repositories as repo
from app.models.orm import AuthUser
from app.schemas.auth import LoginRequest, LoginResponse, MeResponse, RegisterRequest, UserOut

from worker.jobs.attack_engine import ATTACK_QUERIES

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register/", status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    if not body.username or not body.password:
        raise HTTPException(status_code=400, detail="username and password required")
    if db.scalar(select(AuthUser.id).where(AuthUser.username == body.username)):
        raise HTTPException(status_code=400, detail={"username": ["A user with this username already exists."]})
    repo.create_user_with_tenant(
        db,
        username=body.username.strip(),
        email=body.email.strip() or body.username.strip(),
        password_hash=hash_password(body.password),
        tenant_name=f"{body.username.strip()}'s workspace",
    )
    return {"detail": "Account created successfully"}


@router.post("/login/", response_model=LoginResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    if not body.username or not body.password:
        raise HTTPException(status_code=400, detail="username and password required")
    user = repo.get_user_by_username_or_email(db, body.username)
    if user is None or not verify_password(body.password, user.password):#enumerate timing attack , same generic error message 
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = repo.get_or_create_token(db, user.id)#idempotent, tradeoff device session management , jwt expiry management is complex and is only needed for multidevice/microservices
    return LoginResponse(
        token=token.key,
        user=UserOut(
            id=user.id,
            email=user.email or user.username,
            username=user.username,
        ),
    )


@router.post("/logout/", status_code=status.HTTP_200_OK)
def logout(user: AuthUser = Depends(get_current_user), db: Session = Depends(get_db)):
    repo.delete_user_token(db, user.id)
    return {}


@router.get("/attack-engine/queries/")
def attack_engine_catalog():
    return ATTACK_QUERIES


@router.get("/me/", response_model=MeResponse)
def me(user: AuthUser = Depends(get_current_user), db: Session = Depends(get_db)):
    profile = repo.get_user_profile(db, user.id)
    tenant_id = profile.tenant_id if profile else None
    return MeResponse(
        id=user.id,
        email=user.email or user.username,
        username=user.username,
        tenant_id=tenant_id,
    )
