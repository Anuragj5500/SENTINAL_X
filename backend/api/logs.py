from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_, text
from typing import Optional
from datetime import datetime
from backend.database import get_db
from backend.models import Log, Severity, User
from backend.schemas import LogIngest, LogOut
from backend.auth.rbac import get_current_user
from backend.normalization.normalizer import normalize_log
from backend.detection.engine import run_detection
import math

router = APIRouter(prefix="/logs", tags=["Logs"])


@router.post("/ingest", status_code=202)
async def ingest_log(data: LogIngest, db: AsyncSession = Depends(get_db)):
    """Bulk log ingestion endpoint (no auth for agent use — use API key in prod)."""
    normalized = normalize_log(data.model_dump())
    
    log = Log(
        timestamp=data.timestamp,
        hostname=data.hostname,
        source_ip=data.source_ip,
        destination_ip=data.destination_ip,
        user=data.user,
        event_type=data.event_type,
        event_id=data.event_id,
        source=data.source,
        severity=data.severity,
        command=data.command,
        process_name=data.process_name,
        file_path=data.file_path,
        hash_value=data.hash_value,
        status=data.status,
        raw_log=data.raw_log,
        normalized=normalized
    )
    db.add(log)
    await db.flush()
    
    # Run detection asynchronously
    await run_detection(log, db)
    
    return {"log_id": log.id, "status": "ingested"}


@router.post("/ingest/bulk", status_code=202)
@router.post("/batch", status_code=202)
async def ingest_bulk(logs: list[LogIngest], db: AsyncSession = Depends(get_db)):
    """Bulk ingestion for agent batches."""
    ids = []
    for data in logs:
        normalized = normalize_log(data.model_dump())
        log = Log(
            timestamp=data.timestamp,
            hostname=data.hostname,
            source_ip=data.source_ip,
            destination_ip=data.destination_ip,
            user=data.user,
            event_type=data.event_type,
            event_id=data.event_id,
            source=data.source,
            severity=data.severity,
            command=data.command,
            process_name=data.process_name,
            file_path=data.file_path,
            hash_value=data.hash_value,
            status=data.status,
            raw_log=data.raw_log,
            normalized=normalized
        )
        db.add(log)
        await db.flush()
        await run_detection(log, db)
        ids.append(log.id)
    return {"ingested": len(ids), "log_ids": ids}


@router.get("", response_model=dict)
async def search_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    source: Optional[str] = None,
    hostname: Optional[str] = None,
    user: Optional[str] = None,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    severity: Optional[Severity] = None,
    q: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Log)
    count_query = select(func.count(Log.id))
    
    filters = []
    if source:
        filters.append(Log.source.ilike(f"%{source}%"))
    if hostname:
        filters.append(Log.hostname.ilike(f"%{hostname}%"))
    if user:
        filters.append(Log.user.ilike(f"%{user}%"))
    if event_type:
        filters.append(Log.event_type.ilike(f"%{event_type}%"))
    if source_ip:
        filters.append(Log.source_ip.ilike(f"%{source_ip}%"))
    if severity:
        filters.append(Log.severity == severity)
    if q:
        filters.append(or_(
            Log.raw_log.ilike(f"%{q}%"),
            Log.command.ilike(f"%{q}%"),
            Log.hostname.ilike(f"%{q}%"),
            Log.user.ilike(f"%{q}%"),
        ))
    
    if filters:
        query = query.where(and_(*filters))
        count_query = count_query.where(and_(*filters))
    
    total = (await db.execute(count_query)).scalar()
    offset = (page - 1) * page_size
    result = await db.execute(query.order_by(Log.timestamp.desc()).offset(offset).limit(page_size))
    logs = result.scalars().all()
    
    return {
        "items": [LogOut.model_validate(l).model_dump() for l in logs],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": math.ceil(total / page_size)
    }
