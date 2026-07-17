"""
Compliance API — Evaluate security posture against PCI DSS, SOC2, ISO27001, HIPAA, GDPR.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from backend.database import get_db
from backend.models import User, UserRole
from backend.auth.rbac import get_current_user, require_roles
from backend.compliance import (
    evaluate_framework, evaluate_all_frameworks, FRAMEWORKS
)

router = APIRouter(prefix="/compliance", tags=["Compliance"])


@router.get("/frameworks")
async def list_frameworks(current_user: User = Depends(get_current_user)):
    """List all available compliance frameworks."""
    return [
        {
            "id": fid,
            "name": fw["name"],
            "controls_count": len(fw["controls"]),
        }
        for fid, fw in FRAMEWORKS.items()
    ]


@router.get("/evaluate/{framework_id}")
async def evaluate(
    framework_id: str,
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Evaluate a specific compliance framework."""
    if framework_id not in FRAMEWORKS:
        raise HTTPException(400, f"Unknown framework: {framework_id}. Available: {list(FRAMEWORKS.keys())}")
    return await evaluate_framework(framework_id, db, days)


@router.get("/evaluate")
async def evaluate_all(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Evaluate all compliance frameworks and return overall posture."""
    return await evaluate_all_frameworks(db, days)


@router.get("/posture")
async def posture_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Quick compliance posture summary — scores only."""
    all_results = await evaluate_all_frameworks(db, 30)
    summary = []
    for fid, result in all_results["frameworks"].items():
        summary.append({
            "framework": result["framework"],
            "framework_id": fid,
            "score": result["overall_score"],
            "status": result["overall_status"],
            "passed": result["summary"]["passed"],
            "failed": result["summary"]["failed"],
        })
    return {
        "overall_posture_score": all_results["overall_posture_score"],
        "frameworks": summary,
    }
