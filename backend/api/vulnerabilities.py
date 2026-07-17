"""
Vulnerability Management API — Track, import, and correlate vulnerabilities.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from typing import Optional, List
from pydantic import BaseModel
import math

from backend.database import get_db
from backend.models import Vulnerability, Asset, User, Severity, UserRole
from backend.auth.rbac import get_current_user, require_roles

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


# ─────────────────────────────── Schemas ─────────────────────────────────────

class VulnCreate(BaseModel):
    asset_id: Optional[str] = None
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: Severity
    cvss_score: float = 0.0
    affected_software: Optional[str] = None
    remediation: Optional[str] = None


class VulnUpdate(BaseModel):
    status: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None


class VulnOut(BaseModel):
    id: str
    asset_id: Optional[str]
    cve_id: Optional[str]
    title: str
    description: Optional[str]
    severity: Severity
    cvss_score: float
    affected_software: Optional[str]
    remediation: Optional[str]
    status: str
    discovered_at: datetime
    model_config = {"from_attributes": True}


# ─────────────────────────────── Routes ──────────────────────────────────────

@router.get("", response_model=dict)
async def list_vulnerabilities(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[Severity] = None,
    status: Optional[str] = None,
    asset_id: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Vulnerability)
    count_query = select(func.count(Vulnerability.id))

    filters = []
    if severity:
        filters.append(Vulnerability.severity == severity)
    if status:
        filters.append(Vulnerability.status == status)
    if asset_id:
        filters.append(Vulnerability.asset_id == asset_id)
    if search:
        from sqlalchemy import or_
        filters.append(or_(
            Vulnerability.title.ilike(f"%{search}%"),
            Vulnerability.cve_id.ilike(f"%{search}%"),
            Vulnerability.affected_software.ilike(f"%{search}%"),
        ))

    if filters:
        query = query.where(and_(*filters))
        count_query = count_query.where(and_(*filters))

    total = (await db.execute(count_query)).scalar()
    offset = (page - 1) * page_size
    result = await db.execute(
        query.order_by(Vulnerability.cvss_score.desc()).offset(offset).limit(page_size)
    )
    vulns = result.scalars().all()

    return {
        "items": [VulnOut.model_validate(v).model_dump() for v in vulns],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": math.ceil(total / page_size) if total else 1,
    }


@router.post("", response_model=VulnOut, status_code=201)
async def create_vulnerability(
    data: VulnCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    vuln = Vulnerability(**data.model_dump())
    db.add(vuln)
    await db.flush()
    return vuln


@router.get("/stats")
async def vulnerability_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total = (await db.execute(select(func.count(Vulnerability.id)))).scalar()
    open_count = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.status == "open")
    )).scalar()

    by_severity = (await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
    )).all()

    avg_cvss = (await db.execute(select(func.avg(Vulnerability.cvss_score)))).scalar()

    # Critical CVEs
    critical_cves = (await db.execute(
        select(Vulnerability.cve_id, Vulnerability.title, Vulnerability.cvss_score)
        .where(and_(
            Vulnerability.severity == Severity.critical,
            Vulnerability.cve_id.isnot(None)
        ))
        .order_by(Vulnerability.cvss_score.desc())
        .limit(10)
    )).all()

    return {
        "total": total,
        "open": open_count,
        "avg_cvss_score": round(avg_cvss or 0, 2),
        "by_severity": {r[0].value: r[1] for r in by_severity},
        "critical_cves": [
            {"cve_id": r[0], "title": r[1], "cvss_score": r[2]}
            for r in critical_cves
        ],
    }


@router.get("/{vuln_id}", response_model=VulnOut)
async def get_vulnerability(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")
    return vuln


@router.patch("/{vuln_id}", response_model=VulnOut)
async def update_vulnerability(
    vuln_id: str,
    data: VulnUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")
    for field, value in data.model_dump(exclude_none=True).items():
        setattr(vuln, field, value)
    await db.flush()
    return vuln


@router.delete("/{vuln_id}", status_code=204)
async def delete_vulnerability(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.super_admin, UserRole.soc_manager)),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")
    await db.delete(vuln)


@router.get("/asset/{asset_id}")
async def asset_vulnerabilities(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all vulnerabilities for a specific asset."""
    result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.asset_id == asset_id)
        .order_by(Vulnerability.cvss_score.desc())
    )
    vulns = result.scalars().all()
    return [VulnOut.model_validate(v).model_dump() for v in vulns]
