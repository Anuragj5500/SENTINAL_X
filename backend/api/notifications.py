"""
Notifications API — Manage notification channels, test them, and send manual alerts.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional, List

from backend.database import get_db
from backend.models import User, UserRole
from backend.auth.rbac import get_current_user, require_roles
from backend.notifications import (
    notify, notify_alert, notify_incident,
    get_channel_status, NotificationChannel,
    send_email, send_slack, send_telegram, send_discord, send_teams,
)

router = APIRouter(prefix="/notifications", tags=["Notifications"])


class TestNotification(BaseModel):
    channel: str  # email, slack, telegram, discord, teams
    message: Optional[str] = None


class ManualNotification(BaseModel):
    subject: str
    message: str
    severity: str = "medium"
    channels: Optional[List[str]] = None


@router.get("/status")
async def notification_status(current_user: User = Depends(get_current_user)):
    """Get configuration status of all notification channels."""
    return get_channel_status()


@router.post("/test")
async def test_notification(
    data: TestNotification,
    current_user: User = Depends(require_roles(UserRole.super_admin, UserRole.soc_manager)),
):
    """Test a specific notification channel."""
    msg = data.message or f"🧪 SentinelX test notification — sent by {current_user.username}"
    subject = "Test Notification"

    channel_map = {
        "email": lambda: send_email(subject, msg),
        "slack": lambda: send_slack(msg),
        "telegram": lambda: send_telegram(msg),
        "discord": lambda: send_discord(msg),
        "teams": lambda: send_teams(msg),
    }

    sender = channel_map.get(data.channel)
    if not sender:
        raise HTTPException(400, f"Unknown channel: {data.channel}. Available: {list(channel_map.keys())}")

    result = await sender()
    return {"channel": data.channel, "result": result}


@router.post("/send")
async def send_manual(
    data: ManualNotification,
    current_user: User = Depends(require_roles(
        UserRole.super_admin, UserRole.soc_manager, UserRole.analyst
    )),
):
    """Send a manual notification across channels."""
    channels = None
    if data.channels:
        try:
            channels = [NotificationChannel(c) for c in data.channels]
        except ValueError as e:
            raise HTTPException(400, f"Invalid channel: {e}")

    results = await notify(data.subject, data.message, data.severity, channels)
    return {"sent": len(results), "results": results}
