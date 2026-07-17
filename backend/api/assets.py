from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_
from typing import Optional
from backend.database import get_db
from backend.models import Asset, AssetCriticality, User
from backend.schemas import AssetCreate, AssetOut
from backend.auth.rbac import get_current_user
import math
import csv
import io

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get("", response_model=dict)
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    criticality: Optional[AssetCriticality] = None,
    search: Optional[str] = None,
    department: Optional[str] = None,
    tag: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Asset)
    count_query = select(func.count(Asset.id))
    
    filters = [Asset.is_active == True]
    if criticality:
        filters.append(Asset.criticality == criticality)
    if department:
        filters.append(Asset.department.ilike(f"%{department}%"))
    if search:
        filters.append(or_(
            Asset.hostname.ilike(f"%{search}%"),
            Asset.ip_address.ilike(f"%{search}%"),
            Asset.owner.ilike(f"%{search}%"),
        ))
    
    query = query.where(and_(*filters))
    count_query = count_query.where(and_(*filters))
    
    total = (await db.execute(count_query)).scalar()
    offset = (page - 1) * page_size
    result = await db.execute(query.order_by(Asset.hostname).offset(offset).limit(page_size))
    assets = result.scalars().all()
    
    return {
        "items": [AssetOut.model_validate(a).model_dump() for a in assets],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": math.ceil(total / page_size)
    }


@router.post("", response_model=AssetOut, status_code=201)
async def create_asset(data: AssetCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    asset = Asset(**data.model_dump())
    db.add(asset)
    await db.flush()
    return asset


@router.get("/topology")
async def get_network_topology(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve assets and active connections parsed from logs to build the topology map."""
    from backend.models import Log, Alert
    
    # 1. Fetch active internal assets
    assets_res = await db.execute(select(Asset).where(Asset.is_active == True))
    assets = assets_res.scalars().all()
    
    # 2. Query distinct active connections from Logs table
    conn_res = await db.execute(
        select(Log.source_ip, Log.destination_ip, Log.severity, func.count(Log.id))
        .where(and_(
            Log.source_ip.isnot(None),
            Log.destination_ip.isnot(None),
            Log.source_ip != "",
            Log.destination_ip != "",
            Log.source_ip != "127.0.0.1",
            Log.destination_ip != "127.0.0.1",
            Log.source_ip != Log.destination_ip
        ))
        .group_by(Log.source_ip, Log.destination_ip, Log.severity)
        .limit(100)
    )
    connections = conn_res.all()
    
    # 3. Query active alerts to find compromised IPs
    alerts_res = await db.execute(
        select(Alert.source_ip, Alert.severity)
        .where(and_(Alert.source_ip.isnot(None), Alert.source_ip != ""))
    )
    alert_rows = alerts_res.all()
    
    alert_ips = {}
    for source_ip, severity in alert_rows:
        sev_val = severity.value if hasattr(severity, "value") else str(severity)
        # Store highest severity
        if source_ip not in alert_ips:
            alert_ips[source_ip] = sev_val
        else:
            sev_levels = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
            current_level = sev_levels.get(alert_ips[source_ip], 0)
            new_level = sev_levels.get(sev_val, 0)
            if new_level > current_level:
                alert_ips[source_ip] = sev_val

    # 4. Construct Nodes & Edges
    nodes = {}
    edges_tracker = {}
    
    # Add internal assets as nodes
    for a in assets:
        ip = a.ip_address
        status = "healthy"
        severity = None
        if ip in alert_ips:
            status = "compromised"
            severity = alert_ips[ip]
            
        nodes[ip] = {
            "id": ip,
            "label": a.hostname or ip,
            "type": "internal",
            "criticality": a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality),
            "status": status,
            "severity": severity,
            "os": a.os_type or "unknown",
            "department": a.department or "IT"
        }
        
    # Build edges and capture external IP nodes
    for src, dst, severity, count in connections:
        # Register nodes if not registered
        for ip in (src, dst):
            if ip not in nodes:
                status = "healthy"
                sev = None
                if ip in alert_ips:
                    status = "compromised"
                    sev = alert_ips[ip]
                    
                nodes[ip] = {
                    "id": ip,
                    "label": ip,
                    "type": "external",
                    "criticality": "low",
                    "status": status,
                    "severity": sev,
                    "os": "unknown",
                    "department": "External Net"
                }
                
        edge_key = f"{src}->{dst}"
        sev_val = severity.value if hasattr(severity, "value") else str(severity)
        
        if edge_key not in edges_tracker:
            edges_tracker[edge_key] = {
                "source": src,
                "target": dst,
                "count": count,
                "severity": sev_val,
                "is_anomalous": src in alert_ips or dst in alert_ips
            }
        else:
            edges_tracker[edge_key]["count"] += count
            # Keep highest severity
            sev_levels = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
            current_level = sev_levels.get(edges_tracker[edge_key]["severity"], 0)
            new_level = sev_levels.get(sev_val, 0)
            if new_level > current_level:
                edges_tracker[edge_key]["severity"] = sev_val
                
    return {
        "nodes": list(nodes.values()),
        "edges": list(edges_tracker.values())
    }


@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(asset_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.patch("/{asset_id}", response_model=AssetOut)
async def update_asset(
    asset_id: str,
    data: AssetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    for field, value in data.model_dump(exclude_none=True).items():
        setattr(asset, field, value)
    await db.flush()
    return asset


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(asset_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset.is_active = False
    await db.flush()


@router.post("/import-csv")
async def import_csv(file: UploadFile = File(...), db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    content = await file.read()
    reader = csv.DictReader(io.StringIO(content.decode()))
    imported = 0
    for row in reader:
        asset = Asset(
            hostname=row.get("hostname", "unknown"),
            ip_address=row.get("ip_address", "0.0.0.0"),
            mac_address=row.get("mac_address"),
            os_type=row.get("os_type"),
            department=row.get("department"),
            owner=row.get("owner"),
        )
        db.add(asset)
        imported += 1
    await db.flush()
    return {"imported": imported}


@router.get("/stats/summary")
async def asset_summary(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    by_criticality = (await db.execute(
        select(Asset.criticality, func.count(Asset.id)).where(Asset.is_active == True).group_by(Asset.criticality)
    )).all()
    by_os = (await db.execute(
        select(Asset.os_type, func.count(Asset.id)).where(Asset.is_active == True).group_by(Asset.os_type).limit(10)
    )).all()
    by_department = (await db.execute(
        select(Asset.department, func.count(Asset.id)).where(
            and_(Asset.is_active == True, Asset.department.isnot(None))
        ).group_by(Asset.department).order_by(func.count(Asset.id).desc())
    )).all()
    return {
        "by_criticality": {r[0].value: r[1] for r in by_criticality},
        "by_os": {(r[0] or "Unknown"): r[1] for r in by_os},
        "by_department": {(r[0] or "Unassigned"): r[1] for r in by_department},
    }


@router.get("/groups")
async def asset_groups(
    group_by: str = Query("department", description="Group assets by: department, criticality, os_type"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Group assets by a specified attribute."""
    column_map = {
        "department": Asset.department,
        "criticality": Asset.criticality,
        "os_type": Asset.os_type,
    }
    column = column_map.get(group_by)
    if not column:
        raise HTTPException(400, f"Invalid group_by: {group_by}. Use: {', '.join(column_map.keys())}")

    rows = (await db.execute(
        select(column, func.count(Asset.id), func.avg(Asset.risk_score))
        .where(Asset.is_active == True)
        .group_by(column)
        .order_by(func.count(Asset.id).desc())
    )).all()

    return [
        {
            "group": str(r[0].value) if hasattr(r[0], 'value') else str(r[0] or "Unknown"),
            "count": r[1],
            "avg_risk_score": round(r[2] or 0, 1),
        }
        for r in rows
    ]


@router.get("/at-risk")
async def at_risk_assets(
    threshold: float = Query(70.0, ge=0, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get assets with risk scores above a threshold."""
    result = await db.execute(
        select(Asset)
        .where(and_(Asset.is_active == True, Asset.risk_score >= threshold))
        .order_by(Asset.risk_score.desc())
        .limit(50)
    )
    assets = result.scalars().all()
    return [AssetOut.model_validate(a).model_dump() for a in assets]

