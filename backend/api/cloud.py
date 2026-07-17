"""
Cloud Security API — Monitor AWS, Azure, and GCP security events.
"""
from fastapi import APIRouter, Depends, Query
from typing import Optional

from backend.models import User
from backend.auth.rbac import get_current_user
from backend.cloud import (
    collect_aws_events, collect_azure_events, collect_gcp_events,
    collect_all_cloud_events, get_cloud_posture,
)

router = APIRouter(prefix="/cloud", tags=["Cloud Security"])


@router.get("/events")
async def cloud_events(
    provider: Optional[str] = Query(None, description="Filter by provider: aws, azure, gcp"),
    count: int = Query(10, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    """Get recent cloud security events (simulated)."""
    if provider == "aws":
        return {"provider": "aws", "events": collect_aws_events(count)}
    elif provider == "azure":
        return {"provider": "azure", "events": collect_azure_events(count)}
    elif provider == "gcp":
        return {"provider": "gcp", "events": collect_gcp_events(count)}
    else:
        return collect_all_cloud_events(count)


@router.get("/posture")
async def cloud_posture(current_user: User = Depends(get_current_user)):
    """Get cloud security posture summary across all providers."""
    return get_cloud_posture()


@router.get("/providers")
async def list_providers(current_user: User = Depends(get_current_user)):
    """List configured cloud providers."""
    return [
        {"id": "aws", "name": "Amazon Web Services", "status": "monitored", "services": ["CloudTrail", "GuardDuty", "IAM", "S3", "EC2"]},
        {"id": "azure", "name": "Microsoft Azure", "status": "monitored", "services": ["Azure AD", "Activity Log", "Key Vault", "NSG"]},
        {"id": "gcp", "name": "Google Cloud Platform", "status": "monitored", "services": ["Audit Logs", "IAM", "VPC", "GCS"]},
    ]
