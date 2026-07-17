from datetime import datetime, timezone, timedelta
from typing import cast
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from backend.database import get_db
from backend.models import User, AuditLog
from backend.schemas import UserCreate, UserLogin, TokenResponse, UserOut, RefreshRequest, MFASetupResponse, MFAVerify, PasswordChange
from backend.auth.jwt import hash_password, verify_password, create_access_token, create_refresh_token, decode_token
from backend.auth.mfa import generate_mfa_secret, get_totp_uri, verify_totp
from backend.auth.rbac import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


async def log_audit(db: AsyncSession, user_id: str, action: str, details: dict, ip: str | None = None):
    log = AuditLog(user_id=user_id, action=action, resource_type="auth", details=details, ip_address=ip)
    db.add(log)


@router.post("/register", response_model=UserOut, status_code=201)
async def register(data: UserCreate, db: AsyncSession = Depends(get_db)):
    # Check existing
    result = await db.execute(select(User).where(
        (User.username == data.username) | (User.email == data.email)
    ))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    user = User(
        username=data.username,
        email=data.email,
        full_name=data.full_name,
        hashed_password=hash_password(data.password),
        role=data.role
    )
    db.add(user)
    await db.flush()
    await log_audit(db, cast(str, user.id), "USER_REGISTERED", {"username": user.username})
    return user


@router.post("/login", response_model=TokenResponse)
async def login(data: UserLogin, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == data.username))
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check lockout
    current_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    if user.locked_until and user.locked_until > current_utc:
        remaining = (user.locked_until - current_utc).seconds
        raise HTTPException(status_code=423, detail=f"Account locked. Try again in {remaining}s")
    
    if not verify_password(data.password, cast(str, user.hashed_password)):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = current_utc + timedelta(minutes=15)  # type: ignore
        await db.flush()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # MFA check
    if user.is_mfa_enabled and user.mfa_secret:
        if not data.totp_code:
            raise HTTPException(status_code=428, detail="MFA code required")
        if not verify_totp(cast(str, user.mfa_secret), data.totp_code):
            raise HTTPException(status_code=401, detail="Invalid MFA code")
    
    # Success
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = current_utc  # type: ignore
    await db.flush()
    
    ip = request.client.host if request.client else "unknown"
    await log_audit(db, cast(str, user.id), "USER_LOGIN", {"ip": ip}, ip)
    
    token_data = {"sub": user.id, "role": user.role.value}
    return TokenResponse(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
        user=UserOut.model_validate(user)
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(data: RefreshRequest, db: AsyncSession = Depends(get_db)):
    payload = decode_token(data.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    
    token_data = {"sub": user.id, "role": user.role.value}
    return TokenResponse(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
        user=UserOut.model_validate(user)
    )


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    secret = generate_mfa_secret()
    current_user.mfa_secret = secret  # type: ignore
    await db.flush()
    uri = get_totp_uri(secret, cast(str, current_user.username))
    return MFASetupResponse(secret=secret, qr_uri=uri)


@router.post("/mfa/verify")
async def verify_mfa(data: MFAVerify, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA not set up")
    if not verify_totp(cast(str, current_user.mfa_secret), data.totp_code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    current_user.is_mfa_enabled = True  # type: ignore
    await db.flush()
    return {"message": "MFA enabled successfully"}


@router.post("/change-password")
async def change_password(data: PasswordChange, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not verify_password(data.current_password, cast(str, current_user.hashed_password)):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    current_user.hashed_password = hash_password(data.new_password)  # type: ignore
    await db.flush()
    await log_audit(db, cast(str, current_user.id), "PASSWORD_CHANGED", {})
    return {"message": "Password changed successfully"}
