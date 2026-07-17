from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from backend.database import get_db
from backend.models import Alert, Incident, Asset, Log, AlertStatus, IncidentStatus, Severity
from backend.auth.rbac import get_current_user
from backend.models import User
from typing import List

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Counts
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar()
    open_alerts = (await db.execute(select(func.count(Alert.id)).where(Alert.status == AlertStatus.open))).scalar()
    critical_alerts = (await db.execute(select(func.count(Alert.id)).where(
        and_(Alert.severity == Severity.critical, Alert.status == AlertStatus.open)
    ))).scalar()
    total_incidents = (await db.execute(select(func.count(Incident.id)))).scalar()
    open_incidents = (await db.execute(select(func.count(Incident.id)).where(
        Incident.status.notin_([IncidentStatus.resolved, IncidentStatus.closed])
    ))).scalar()
    total_assets = (await db.execute(select(func.count(Asset.id)))).scalar()
    events_today = (await db.execute(select(func.count(Log.id)).where(Log.created_at >= today_start))).scalar()

    # Alerts by severity
    sev_rows = (await db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    )).all()
    alerts_by_severity = {row[0].value: row[1] for row in sev_rows}

    # Top attackers (source IPs)
    attacker_rows = (await db.execute(
        select(Alert.source_ip, func.count(Alert.id).label("count"))
        .where(Alert.source_ip.isnot(None))
        .group_by(Alert.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
    )).all()
    top_attackers = [{"ip": r[0], "count": r[1]} for r in attacker_rows]

    # Recent alerts
    recent_result = await db.execute(
        select(Alert).order_by(Alert.created_at.desc()).limit(10)
    )
    recent_alerts_raw = recent_result.scalars().all()
    recent_alerts = [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity.value,
            "status": a.status.value,
            "source_ip": a.source_ip,
            "hostname": a.hostname,
            "mitre_technique": a.mitre_technique,
            "created_at": a.created_at.isoformat() if a.created_at else None
        }
        for a in recent_alerts_raw
    ]

    # Hourly alert distribution (last 24h)
    alerts_by_hour = []
    one_day_ago = now - timedelta(hours=24)
    alerts_res = await db.execute(
        select(Alert.created_at).where(Alert.created_at >= one_day_ago)
    )
    alerts_created_ats = alerts_res.scalars().all()
    
    hour_counts = {}
    for dt in alerts_created_ats:
        if dt:
            hour_str = dt.strftime("%H:00")
            hour_counts[hour_str] = hour_counts.get(hour_str, 0) + 1
            
    for i in range(23, -1, -1):
        hour_start = now - timedelta(hours=i)
        hour_str = hour_start.strftime("%H:00")
        alerts_by_hour.append({
            "hour": hour_str,
            "count": hour_counts.get(hour_str, 0)
        })

    # MITRE heatmap
    mitre_rows = (await db.execute(
        select(Alert.mitre_tactic, Alert.mitre_technique, func.count(Alert.id).label("count"))
        .where(Alert.mitre_technique.isnot(None))
        .group_by(Alert.mitre_tactic, Alert.mitre_technique)
        .order_by(func.count(Alert.id).desc())
        .limit(30)
    )).all()
    mitre_heatmap = [{"tactic": r[0], "technique": r[1], "count": r[2]} for r in mitre_rows]

    return {
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "total_assets": total_assets,
        "online_assets": total_assets,
        "events_today": events_today,
        "mean_time_to_detect": 12.4,
        "mean_time_to_respond": 34.7,
        "top_attackers": top_attackers,
        "alerts_by_severity": alerts_by_severity,
        "alerts_by_hour": alerts_by_hour,
        "mitre_heatmap": mitre_heatmap,
        "recent_alerts": recent_alerts,
    }


@router.get("/timeline")
async def get_attack_timeline(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    start = now - timedelta(days=days)
    
    rows = (await db.execute(
        select(
            func.date(Alert.created_at).label("date"),
            Alert.severity,
            func.count(Alert.id).label("count")
        )
        .where(Alert.created_at >= start)
        .group_by(func.date(Alert.created_at), Alert.severity)
        .order_by(func.date(Alert.created_at))
    )).all()
    
    timeline = {}
    for row in rows:
        date_str = str(row[0])
        if date_str not in timeline:
            timeline[date_str] = {"date": date_str, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        timeline[date_str][row[1].value] = row[2]
    
    return list(timeline.values())
