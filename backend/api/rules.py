"""
Detection Rules API — Full CRUD for Sigma-style detection rules.
Supports enable/disable, stats, and hot-reload.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional
import math

from backend.database import get_db
from backend.models import DetectionRule, Alert, User, UserRole, Severity
from backend.schemas import RuleCreate, RuleOut
from backend.auth.rbac import get_current_user, require_roles

router = APIRouter(prefix="/rules", tags=["Detection Rules"])


@router.get("", response_model=dict)
async def list_rules(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[Severity] = None,
    rule_type: Optional[str] = None,
    enabled: Optional[bool] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(DetectionRule)
    count_query = select(func.count(DetectionRule.id))

    filters = []
    if severity:
        filters.append(DetectionRule.severity == severity)
    if rule_type:
        filters.append(DetectionRule.rule_type == rule_type)
    if enabled is not None:
        filters.append(DetectionRule.enabled == enabled)
    if search:
        from sqlalchemy import or_
        filters.append(or_(
            DetectionRule.name.ilike(f"%{search}%"),
            DetectionRule.description.ilike(f"%{search}%"),
            DetectionRule.mitre_technique.ilike(f"%{search}%"),
            DetectionRule.mitre_tactic.ilike(f"%{search}%"),
        ))

    if filters:
        from sqlalchemy import and_
        query = query.where(and_(*filters))
        count_query = count_query.where(and_(*filters))

    total = (await db.execute(count_query)).scalar()
    offset = (page - 1) * page_size
    result = await db.execute(
        query.order_by(DetectionRule.created_at.desc()).offset(offset).limit(page_size)
    )
    rules = result.scalars().all()

    return {
        "items": [RuleOut.model_validate(r).model_dump() for r in rules],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": math.ceil(total / page_size) if total else 1,
    }


@router.post("", response_model=RuleOut, status_code=201)
async def create_rule(
    data: RuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(
        UserRole.super_admin, UserRole.soc_manager, UserRole.analyst
    )),
):
    rule = DetectionRule(**data.model_dump())
    db.add(rule)
    await db.flush()
    return rule


@router.get("/stats")
async def rule_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total = (await db.execute(select(func.count(DetectionRule.id)))).scalar()
    active = (await db.execute(
        select(func.count(DetectionRule.id)).where(DetectionRule.enabled == True)
    )).scalar()
    by_severity = (await db.execute(
        select(DetectionRule.severity, func.count(DetectionRule.id))
        .group_by(DetectionRule.severity)
    )).all()
    by_type = (await db.execute(
        select(DetectionRule.rule_type, func.count(DetectionRule.id))
        .group_by(DetectionRule.rule_type)
    )).all()

    # Top triggered rules
    top_rules = (await db.execute(
        select(DetectionRule.name, DetectionRule.trigger_count, DetectionRule.severity)
        .where(DetectionRule.trigger_count > 0)
        .order_by(DetectionRule.trigger_count.desc())
        .limit(10)
    )).all()

    return {
        "total_rules": total,
        "active_rules": active,
        "disabled_rules": total - active,
        "by_severity": {r[0].value: r[1] for r in by_severity},
        "by_type": {r[0]: r[1] for r in by_type},
        "top_triggered": [
            {"name": r[0], "trigger_count": r[1], "severity": r[2].value}
            for r in top_rules
        ],
    }


@router.get("/mitre/matrix")
async def mitre_matrix(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get MITRE ATT&CK Matrix coverage and active alert status."""
    from backend.detection.mitre_mapper import get_all_techniques, get_tactics_list
    from datetime import datetime, timezone, timedelta
    
    # 1. Get all enabled rules
    rules_res = await db.execute(select(DetectionRule).where(DetectionRule.enabled == True))
    active_rules = rules_res.scalars().all()
    
    # 2. Get active alerts in the last 7 days
    seven_days_ago = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=7)
    alerts_res = await db.execute(
        select(Alert.mitre_technique, func.count(Alert.id))
        .where(Alert.created_at >= seven_days_ago)
        .group_by(Alert.mitre_technique)
    )
    alert_counts = {r[0]: r[1] for r in alerts_res.all() if r[0]}
    
    # Map enabled rules by technique ID
    rule_coverage = {}
    for rule in active_rules:
        tech = rule.mitre_technique
        if tech:
            if tech not in rule_coverage:
                rule_coverage[tech] = []
            rule_coverage[tech].append({
                "id": rule.id,
                "name": rule.name,
                "severity": rule.severity.value
            })
            
    # 3. Format matrix response
    tactics = get_tactics_list()
    all_techniques = get_all_techniques()
    
    matrix = {}
    for tactic in tactics:
        matrix[tactic] = []
        
    for tech in all_techniques:
        tactic = tech["tactic"]
        if tactic in matrix:
            tech_id = tech["id"]
            # Find if this specific technique or parent has rules/alerts
            covered_rules = rule_coverage.get(tech_id, [])
            alerts_count = alert_counts.get(tech_id, 0)
            
            # Check for subtechniques if parent
            if "." not in tech_id:
                # Parent technique: also aggregate covered rules from subtechniques
                for sub_id, rules in rule_coverage.items():
                    if sub_id.startswith(f"{tech_id}."):
                        covered_rules.extend(rules)
                for sub_id, count in alert_counts.items():
                    if sub_id.startswith(f"{tech_id}."):
                        alerts_count += count
            
            matrix[tactic].append({
                "id": tech_id,
                "name": tech["technique"],
                "sub": tech["sub"],
                "covered": len(covered_rules) > 0,
                "rules": covered_rules,
                "alerts_count": alerts_count,
            })
            
    return {
        "tactics": tactics,
        "matrix": matrix
    }


@router.get("/{rule_id}", response_model=RuleOut)
async def get_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Rule not found")
    return rule


@router.patch("/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: str,
    data: RuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(
        UserRole.super_admin, UserRole.soc_manager
    )),
):
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Rule not found")
    for field, value in data.model_dump(exclude_none=True).items():
        setattr(rule, field, value)
    await db.flush()
    return rule


@router.post("/{rule_id}/toggle")
async def toggle_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Rule not found")
    rule.enabled = not rule.enabled
    await db.flush()
    return {
        "id": rule.id,
        "name": rule.name,
        "enabled": rule.enabled,
        "message": f"Rule {'enabled' if rule.enabled else 'disabled'}",
    }


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.super_admin)),
):
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Rule not found")
    await db.delete(rule)


@router.get("/{rule_id}/alerts")
async def rule_alerts(
    rule_id: str,
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get recent alerts triggered by a specific rule."""
    result = await db.execute(
        select(Alert)
        .where(Alert.rule_id == rule_id)
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )
    alerts = result.scalars().all()
    return [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity.value,
            "status": a.status.value,
            "hostname": a.hostname,
            "created_at": a.created_at,
        }
        for a in alerts
    ]
