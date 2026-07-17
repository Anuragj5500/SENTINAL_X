from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional
from backend.database import get_db
from backend.models import User, Asset, DetectionRule, Playbook, AuditLog, UserRole
from backend.schemas import UserOut, RuleCreate, RuleOut
from backend.auth.rbac import get_current_user, require_roles
from backend.auth.jwt import hash_password
import math

router = APIRouter(prefix="/admin", tags=["Admin"])


# ─────────────── User Management ──────────────────────────────────────────────

@router.get("/users", response_model=list)
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.super_admin, UserRole.soc_manager))
):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    return [UserOut.model_validate(u).model_dump() for u in users]


@router.patch("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    role: UserRole,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.super_admin))
):
    from fastapi import HTTPException
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    user.role = role
    await db.flush()
    return {"message": f"Role updated to {role.value}"}


@router.patch("/users/{user_id}/toggle-active")
async def toggle_user_active(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.super_admin, UserRole.soc_manager))
):
    from fastapi import HTTPException
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    user.is_active = not user.is_active
    await db.flush()
    return {"is_active": user.is_active}


# ─────────────── Detection Rules ──────────────────────────────────────────────

@router.get("/rules", response_model=list)
async def list_rules(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(DetectionRule).order_by(DetectionRule.created_at.desc()))
    rules = result.scalars().all()
    return [RuleOut.model_validate(r).model_dump() for r in rules]


@router.post("/rules", response_model=RuleOut, status_code=201)
async def create_rule(
    data: RuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.super_admin, UserRole.soc_manager, UserRole.analyst))
):
    rule = DetectionRule(**data.model_dump())
    db.add(rule)
    await db.flush()
    return rule


@router.patch("/rules/{rule_id}/toggle")
async def toggle_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from fastapi import HTTPException
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Rule not found")
    rule.enabled = not rule.enabled
    await db.flush()
    return {"enabled": rule.enabled}


# ─────────────── Audit Logs ───────────────────────────────────────────────────

@router.get("/audit-logs")
async def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.super_admin, UserRole.soc_manager, UserRole.auditor))
):
    total = int((await db.execute(select(func.count(AuditLog.id)))).scalar() or 0)
    offset = (page - 1) * page_size
    result = await db.execute(
        select(AuditLog).order_by(AuditLog.created_at.desc()).offset(offset).limit(page_size)
    )
    logs = result.scalars().all()
    return {
        "items": [
            {
                "id": l.id,
                "user_id": l.user_id,
                "action": l.action,
                "resource_type": l.resource_type,
                "details": l.details,
                "ip_address": l.ip_address,
                "created_at": l.created_at
            }
            for l in logs
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": math.ceil(total / page_size)
    }


# ─────────────── System Stats ─────────────────────────────────────────────────

@router.get("/system-stats")
async def system_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.super_admin, UserRole.soc_manager))
):
    return {
        "total_users": (await db.execute(select(func.count(User.id)))).scalar(),
        "total_assets": (await db.execute(select(func.count(Asset.id)))).scalar(),
        "total_rules": (await db.execute(select(func.count(DetectionRule.id)))).scalar(),
        "active_rules": (await db.execute(select(func.count(DetectionRule.id)).where(DetectionRule.enabled == True))).scalar(),
        "total_playbooks": (await db.execute(select(func.count(Playbook.id)))).scalar(),
    }


# ─────────────── API Key Management ───────────────────────────────────────────

from pydantic import BaseModel
from backend.auth.api_keys import generate_api_key
from backend.models import ApiKey
from datetime import datetime, timezone, timedelta

class ApiKeyCreateRequest(BaseModel):
    name: str
    scopes: list[str] = ["logs:write"]
    expires_in_days: Optional[int] = 30


@router.post("/api-keys")
async def create_api_key(
    req: ApiKeyCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.super_admin, UserRole.soc_manager))
):
    """Generate a new API key for agents or integrations."""
    raw_key, key_hash, key_prefix = generate_api_key()
    
    expires_at = None
    if req.expires_in_days:
        expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=req.expires_in_days)
        
    api_key_rec = ApiKey(
        name=req.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        user_id=current_user.id,
        scopes=req.scopes,
        expires_at=expires_at,
    )
    db.add(api_key_rec)
    await db.flush()
    
    # Return the raw key to the user ONLY ONCE on creation
    return {
        "id": api_key_rec.id,
        "name": api_key_rec.name,
        "raw_key": raw_key,  # Securely show only on creation
        "key_prefix": key_prefix,
        "scopes": api_key_rec.scopes,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "created_at": api_key_rec.created_at.isoformat() if api_key_rec.created_at else None,
    }


@router.get("/api-keys")
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.super_admin, UserRole.soc_manager))
):
    """List active/inactive API keys (hashes and raw keys are NOT exposed)."""
    result = await db.execute(
        select(ApiKey).order_by(ApiKey.created_at.desc())
    )
    keys = result.scalars().all()
    return [
        {
            "id": k.id,
            "name": k.name,
            "key_prefix": k.key_prefix,
            "is_active": k.is_active,
            "last_used": k.last_used.isoformat() if k.last_used else None,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "created_at": k.created_at.isoformat() if k.created_at else None,
        }
        for k in keys
    ]


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.super_admin, UserRole.soc_manager))
):
    """Revoke (deactivate) an API key."""
    result = await db.execute(select(ApiKey).where(ApiKey.id == key_id))
    key_record = result.scalar_one_or_none()
    if not key_record:
        from fastapi import HTTPException
        raise HTTPException(404, "API key not found")
    
    key_record.is_active = False
    await db.flush()
    return {"message": "API key successfully revoked"}

