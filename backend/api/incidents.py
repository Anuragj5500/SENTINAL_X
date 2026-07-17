from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_
from typing import Optional
from backend.database import get_db
from backend.models import Incident, IncidentComment, IncidentStatus, User, Alert
from backend.schemas import IncidentCreate, IncidentUpdate, IncidentOut, IncidentCommentCreate
from backend.auth.rbac import get_current_user
import math

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("", response_model=dict)
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: Optional[IncidentStatus] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Incident)
    count_query = select(func.count(Incident.id))
    
    filters = []
    if status:
        filters.append(Incident.status == status)
    if search:
        filters.append(or_(
            Incident.title.ilike(f"%{search}%"),
            Incident.description.ilike(f"%{search}%")
        ))
    
    if filters:
        query = query.where(and_(*filters))
        count_query = count_query.where(and_(*filters))
    
    total = (await db.execute(count_query)).scalar()
    offset = (page - 1) * page_size
    result = await db.execute(query.order_by(Incident.created_at.desc()).offset(offset).limit(page_size))
    incidents = result.scalars().all()
    
    return {
        "items": [IncidentOut.model_validate(i).model_dump() for i in incidents],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": math.ceil(total / page_size)
    }


@router.post("", response_model=IncidentOut, status_code=201)
async def create_incident(data: IncidentCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    incident = Incident(
        **data.model_dump(),
        owner_id=current_user.id,
        timeline=[{
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "Incident created",
            "user": current_user.username
        }]
    )
    db.add(incident)
    await db.flush()
    return incident


@router.get("/{incident_id}", response_model=IncidentOut)
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/{incident_id}", response_model=IncidentOut)
async def update_incident(
    incident_id: str,
    data: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    updates = data.model_dump(exclude_none=True)
    
    # Track status transitions
    if "status" in updates and updates["status"] != incident.status.value:
        new_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": f"Status changed to {updates['status']}",
            "user": current_user.username
        }
        timeline = list(incident.timeline or [])
        timeline.append(new_entry)
        incident.timeline = timeline
        
        if updates["status"] == IncidentStatus.resolved.value:
            incident.resolved_at = datetime.now(timezone.utc)
        elif updates["status"] == IncidentStatus.closed.value:
            incident.closed_at = datetime.now(timezone.utc)
    
    for field, value in updates.items():
        setattr(incident, field, value)
    
    await db.flush()
    return incident


@router.post("/{incident_id}/comments")
async def add_comment(
    incident_id: str,
    data: IncidentCommentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Incident not found")
    
    comment = IncidentComment(incident_id=incident_id, user_id=current_user.id, content=data.content)
    db.add(comment)
    await db.flush()
    return {"id": comment.id, "content": comment.content, "user_id": comment.user_id, "created_at": comment.created_at}


@router.get("/{incident_id}/comments")
async def get_comments(incident_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(
        select(IncidentComment).where(IncidentComment.incident_id == incident_id).order_by(IncidentComment.created_at)
    )
    comments = result.scalars().all()
    return [{"id": c.id, "content": c.content, "user_id": c.user_id, "created_at": c.created_at} for c in comments]


@router.post("/{incident_id}/link-alert/{alert_id}")
async def link_alert(incident_id: str, alert_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    inc_result = await db.execute(select(Incident).where(Incident.id == incident_id))
    if not inc_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Incident not found")
    
    alert_result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = alert_result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.incident_id = incident_id
    await db.flush()
    return {"message": "Alert linked to incident"}
