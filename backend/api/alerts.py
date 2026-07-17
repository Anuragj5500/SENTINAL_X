from fastapi import APIRouter, Depends, HTTPException, Query
# pyrefly: ignore [missing-import]
from sqlalchemy.ext.asyncio import AsyncSession
# pyrefly: ignore [missing-import]
from sqlalchemy import select, func, or_, and_
from typing import Optional, List
from backend.database import get_db
from backend.models import Alert, AlertStatus, Severity, User
from backend.schemas import AlertOut, AlertUpdate, PaginatedResponse
from backend.auth.rbac import get_current_user, require_roles
from backend.models import UserRole
import math

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=dict)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    severity: Optional[Severity] = None,
    status: Optional[AlertStatus] = None,
    search: Optional[str] = None,
    hostname: Optional[str] = None,
    source_ip: Optional[str] = None,
    mitre_tactic: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Alert)
    count_query = select(func.count(Alert.id))
    
    filters = []
    if severity:
        filters.append(Alert.severity == severity)
    if status:
        filters.append(Alert.status == status)
    if hostname:
        filters.append(Alert.hostname.ilike(f"%{hostname}%"))
    if source_ip:
        filters.append(Alert.source_ip.ilike(f"%{source_ip}%"))
    if mitre_tactic:
        filters.append(Alert.mitre_tactic.ilike(f"%{mitre_tactic}%"))
    if search:
        filters.append(or_(
            Alert.title.ilike(f"%{search}%"),
            Alert.description.ilike(f"%{search}%"),
            Alert.source_ip.ilike(f"%{search}%"),
            Alert.hostname.ilike(f"%{search}%"),
        ))
    
    if filters:
        query = query.where(and_(*filters))
        count_query = count_query.where(and_(*filters))
    
    total = (await db.execute(count_query)).scalar()
    
    offset = (page - 1) * page_size
    result = await db.execute(
        query.order_by(Alert.created_at.desc()).offset(offset).limit(page_size)
    )
    alerts = result.scalars().all()
    
    return {
        "items": [AlertOut.model_validate(a).model_dump() for a in alerts],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": math.ceil(total / page_size)
    }


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertOut)
async def update_alert(
    alert_id: str,
    data: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    for field, value in data.model_dump(exclude_none=True).items():
        setattr(alert, field, value)
    await db.flush()
    return alert


@router.delete("/{alert_id}", status_code=204)
async def delete_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.super_admin, UserRole.soc_manager))
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    await db.delete(alert)


@router.post("/{alert_id}/acknowledge", response_model=AlertOut)
async def acknowledge_alert(alert_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = AlertStatus.acknowledged
    alert.assigned_to = current_user.id
    await db.flush()
    return alert


@router.get("/stats/summary")
async def alert_summary(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    by_status = (await db.execute(
        select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
    )).all()
    by_severity = (await db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    )).all()
    return {
        "by_status": {r[0].value: r[1] for r in by_status},
        "by_severity": {r[0].value: r[1] for r in by_severity}
    }
