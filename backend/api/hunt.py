from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_
from typing import Optional
from backend.database import get_db
from backend.models import Log, Alert, User
from backend.auth.rbac import get_current_user

router = APIRouter(prefix="/hunt", tags=["Threat Hunting"])


def _parse_kql_query(q: str, model):
    """
    Parses a KQL-like search string into a SQLAlchemy filter.
    Example: event_type:process_creation AND command:"cmd.exe" AND NOT user:SYSTEM
    """
    from sqlalchemy import and_, or_, not_
    import re
    
    if not q or not q.strip():
        return None
        
    # Split by logical AND operators (case-insensitive)
    parts = re.split(r'\s+AND\s+', q, flags=re.IGNORECASE)
    
    sqlalchemy_filters = []
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
            
        # Check for negation
        is_negated = False
        if part.upper().startswith("NOT "):
            is_negated = True
            part = part[4:].strip()
            
        # Check if it is a key:value pair
        match = re.match(r'^([\w_]+)\s*:\s*(?:"([^"]*)"|(\S+))$', part)
        if match:
            key = match.group(1).lower()
            val = match.group(2) or match.group(3)
            
            # Map key to model attribute
            if hasattr(model, key):
                col = getattr(model, key)
                f = col.ilike(f"%{val}%")
                if is_negated:
                    sqlalchemy_filters.append(not_(f))
                else:
                    sqlalchemy_filters.append(f)
            else:
                # If key is not in model, map common aliases
                mapped = False
                if model.__name__ == "Alert":
                    aliases = {
                        "event_type": "mitre_tactic",
                    }
                    if key in aliases and hasattr(model, aliases[key]):
                        col = getattr(model, aliases[key])
                        f = col.ilike(f"%{val}%")
                        if is_negated:
                            sqlalchemy_filters.append(not_(f))
                        else:
                            sqlalchemy_filters.append(f)
                        mapped = True
                
                # If still not mapped, skip
                if not mapped:
                    pass
        else:
            # Free text search across common text fields
            free_text_filters = []
            if model.__name__ == "Log":
                fields = ["raw_log", "command", "hostname", "user", "process_name"]
            else:
                fields = ["title", "description", "hostname", "user"]
                
            for field in fields:
                if hasattr(model, field):
                    free_text_filters.append(getattr(model, field).ilike(f"%{part}%"))
                    
            if free_text_filters:
                combined_free = or_(*free_text_filters)
                if is_negated:
                    sqlalchemy_filters.append(not_(combined_free))
                else:
                    sqlalchemy_filters.append(combined_free)
                    
    if sqlalchemy_filters:
        return and_(*sqlalchemy_filters)
    return None


@router.get("/search")
async def threat_hunt(
    q: Optional[str] = Query(None, description="Free text query"),
    process_name: Optional[str] = None,
    hostname: Optional[str] = None,
    source_ip: Optional[str] = None,
    user: Optional[str] = None,
    command: Optional[str] = None,
    event_type: Optional[str] = None,
    hash_value: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Analyst threat hunting search across all logs."""
    import math
    
    log_query = select(Log)
    alert_query = select(Alert)
    
    log_filters = []
    alert_filters = []
    
    if q:
        log_parsed = _parse_kql_query(q, Log)
        if log_parsed is not None:
            log_filters.append(log_parsed)
            
        alert_parsed = _parse_kql_query(q, Alert)
        if alert_parsed is not None:
            alert_filters.append(alert_parsed)
    
    if process_name:
        log_filters.append(Log.process_name.ilike(f"%{process_name}%"))
    if hostname:
        log_filters.append(Log.hostname.ilike(f"%{hostname}%"))
        alert_filters.append(Alert.hostname.ilike(f"%{hostname}%"))
    if source_ip:
        log_filters.append(Log.source_ip.ilike(f"%{source_ip}%"))
        alert_filters.append(Alert.source_ip.ilike(f"%{source_ip}%"))
    if user:
        log_filters.append(Log.user.ilike(f"%{user}%"))
        alert_filters.append(Alert.user.ilike(f"%{user}%"))
    if command:
        log_filters.append(Log.command.ilike(f"%{command}%"))
    if event_type:
        log_filters.append(Log.event_type.ilike(f"%{event_type}%"))
    if hash_value:
        log_filters.append(Log.hash_value.ilike(f"%{hash_value}%"))
    
    if log_filters:
        log_query = log_query.where(and_(*log_filters))
    if alert_filters:
        alert_query = alert_query.where(and_(*alert_filters))
    
    offset = (page - 1) * page_size
    
    logs_result = await db.execute(
        log_query.order_by(Log.timestamp.desc()).offset(offset).limit(page_size // 2)
    )
    alerts_result = await db.execute(
        alert_query.order_by(Alert.created_at.desc()).limit(page_size // 2)
    )
    
    logs = logs_result.scalars().all()
    alerts = alerts_result.scalars().all()
    
    count_query = select(func.count(Log.id))
    if log_filters:
        count_query = count_query.where(and_(*log_filters))
    log_count = (await db.execute(count_query)).scalar()
    
    return {
        "logs": [
            {
                "id": l.id,
                "timestamp": l.timestamp,
                "hostname": l.hostname,
                "source_ip": l.source_ip,
                "user": l.user,
                "event_type": l.event_type,
                "process_name": l.process_name,
                "command": l.command,
                "severity": l.severity.value,
                "source": l.source
            }
            for l in logs
        ],
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity.value,
                "status": a.status.value,
                "hostname": a.hostname,
                "source_ip": a.source_ip,
                "mitre_technique": a.mitre_technique,
                "mitre_tactic": a.mitre_tactic,
                "created_at": a.created_at
            }
            for a in alerts
        ],
        "log_count": log_count,
        "page": page,
        "page_size": page_size,
        "pages": math.ceil(log_count / page_size) if log_count else 1
    }


@router.get("/saved-searches")
async def saved_searches(current_user: User = Depends(get_current_user)):
    """Return pre-built hunt queries."""
    return [
        {"name": "Mimikatz Execution", "params": {"process_name": "mimikatz", "q": "sekurlsa"}},
        {"name": "Encoded PowerShell", "params": {"command": "-EncodedCommand"}},
        {"name": "PsExec Activity", "params": {"process_name": "psexec"}},
        {"name": "Admin Account Creation", "params": {"event_type": "user_account_created"}},
        {"name": "Failed Logins Burst", "params": {"event_type": "authentication_failure"}},
        {"name": "Suspicious Cron", "params": {"command": "crontab"}},
        {"name": "Ransomware Extensions", "params": {"command": ".encrypted"}},
        {"name": "DNS Tunneling Indicators", "params": {"event_type": "dns_query"}},
    ]
