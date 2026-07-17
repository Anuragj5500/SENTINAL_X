from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from backend.database import get_db
from backend.models import User, UserRole
from backend.auth.jwt import decode_token

bearer_scheme = HTTPBearer()

# Permission hierarchy
ROLE_PERMISSIONS = {
    UserRole.super_admin:    {"*"},
    UserRole.soc_manager:    {"read", "write", "manage_users", "manage_rules", "manage_playbooks", "view_reports"},
    UserRole.analyst:        {"read", "write", "create_alerts", "update_incidents"},
    UserRole.threat_hunter:  {"read", "write", "threat_hunt", "create_alerts"},
    UserRole.responder:      {"read", "write", "execute_playbooks", "update_incidents"},
    UserRole.auditor:        {"read", "view_audit_logs", "view_reports"},
    UserRole.readonly:       {"read"},
}


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    token = credentials.credentials
    payload = decode_token(token)
    
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    return user


def require_roles(*roles: UserRole):
    async def _dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles and current_user.role != UserRole.super_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {[r.value for r in roles]}"
            )
        return current_user
    return _dependency


def require_permission(permission: str):
    async def _dependency(current_user: User = Depends(get_current_user)) -> User:
        perms = ROLE_PERMISSIONS.get(current_user.role, set())
        if "*" not in perms and permission not in perms:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission}"
            )
        return current_user
    return _dependency
