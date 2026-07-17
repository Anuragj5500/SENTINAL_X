"""
SentinelX Unified Notification Manager
Handles multi-channel notifications with severity-based routing:
Email (SMTP), Slack, Telegram, Discord, Microsoft Teams.
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum

import httpx
from backend.config import settings

logger = logging.getLogger("sentinelx.notifications")


class NotificationChannel(str, Enum):
    email = "email"
    slack = "slack"
    telegram = "telegram"
    discord = "discord"
    teams = "teams"


# Severity → channels routing (configurable)
DEFAULT_ROUTING = {
    "critical": [NotificationChannel.slack, NotificationChannel.telegram, NotificationChannel.email, NotificationChannel.discord, NotificationChannel.teams],
    "high": [NotificationChannel.slack, NotificationChannel.telegram, NotificationChannel.email],
    "medium": [NotificationChannel.slack, NotificationChannel.email],
    "low": [NotificationChannel.email],
    "info": [],
}


# ─────────────────────────── Channel Senders ──────────────────────────────────

async def send_email(subject: str, body: str, to: Optional[str] = None) -> Dict[str, Any]:
    """Send email via SMTP using aiosmtplib if available, otherwise standard smtplib."""
    smtp_host = settings.SMTP_HOST
    smtp_user = settings.SMTP_USER
    smtp_pass = settings.SMTP_PASS

    if not smtp_host or not smtp_user or not smtp_pass:
        return {"channel": "email", "status": "skipped", "reason": "SMTP not configured"}

    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        recipient = to or smtp_user

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🛡️ SentinelX — {subject}"
        msg["From"] = smtp_user
        msg["To"] = recipient

        # Plain text
        msg.attach(MIMEText(body, "plain"))

        # HTML version
        html_body = f"""
        <div style="font-family: -apple-system, sans-serif; max-width: 600px; margin: 0 auto;
                    background: #0d1117; color: #e6edf3; padding: 24px; border-radius: 12px;">
            <div style="border-bottom: 2px solid #00d4ff; padding-bottom: 12px; margin-bottom: 16px;">
                <h2 style="color: #00d4ff; margin: 0;">🛡️ SentinelX Alert</h2>
            </div>
            <h3 style="color: #f0f6fc;">{subject}</h3>
            <pre style="background: #161b22; padding: 16px; border-radius: 8px;
                       color: #8b949e; white-space: pre-wrap;">{body}</pre>
            <p style="color: #484f58; font-size: 12px; margin-top: 20px;">
                Sent by SentinelX SIEM Platform • {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
            </p>
        </div>
        """
        msg.attach(MIMEText(html_body, "html"))

        # Send via SMTP in a thread to not block async loop
        def _send():
            with smtplib.SMTP(smtp_host, settings.SMTP_PORT) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _send)

        return {"channel": "email", "status": "sent", "to": recipient}
    except Exception as e:
        logger.error(f"Email send failed: {e}")
        return {"channel": "email", "status": "error", "error": str(e)}


async def send_slack(message: str) -> Dict[str, Any]:
    """Send message to Slack via webhook."""
    if not settings.SLACK_WEBHOOK_URL:
        return {"channel": "slack", "status": "skipped", "reason": "Slack webhook not configured"}

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                settings.SLACK_WEBHOOK_URL,
                json={"text": message},
                timeout=10,
            )
            return {
                "channel": "slack",
                "status": "sent" if resp.status_code == 200 else "error",
                "http_status": resp.status_code,
            }
    except Exception as e:
        logger.error(f"Slack send failed: {e}")
        return {"channel": "slack", "status": "error", "error": str(e)}


async def send_telegram(message: str) -> Dict[str, Any]:
    """Send message to Telegram via Bot API."""
    if not (settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID):
        return {"channel": "telegram", "status": "skipped", "reason": "Telegram not configured"}

    try:
        async with httpx.AsyncClient() as client:
            url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
            resp = await client.post(
                url,
                json={
                    "chat_id": settings.TELEGRAM_CHAT_ID,
                    "text": message,
                    "parse_mode": "HTML",
                },
                timeout=10,
            )
            return {
                "channel": "telegram",
                "status": "sent" if resp.status_code == 200 else "error",
                "http_status": resp.status_code,
            }
    except Exception as e:
        logger.error(f"Telegram send failed: {e}")
        return {"channel": "telegram", "status": "error", "error": str(e)}


async def send_discord(message: str) -> Dict[str, Any]:
    """Send message to Discord via webhook."""
    webhook_url = getattr(settings, "DISCORD_WEBHOOK_URL", None)
    if not webhook_url:
        return {"channel": "discord", "status": "skipped", "reason": "Discord webhook not configured"}

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                webhook_url,
                json={"content": message},
                timeout=10,
            )
            return {
                "channel": "discord",
                "status": "sent" if resp.status_code in (200, 204) else "error",
                "http_status": resp.status_code,
            }
    except Exception as e:
        logger.error(f"Discord send failed: {e}")
        return {"channel": "discord", "status": "error", "error": str(e)}


async def send_teams(message: str) -> Dict[str, Any]:
    """Send message to Microsoft Teams via webhook."""
    webhook_url = getattr(settings, "TEAMS_WEBHOOK_URL", None)
    if not webhook_url:
        return {"channel": "teams", "status": "skipped", "reason": "Teams webhook not configured"}

    try:
        # Teams Incoming Webhook (Adaptive Card format)
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "00d4ff",
            "summary": "SentinelX Alert",
            "sections": [{
                "activityTitle": "🛡️ SentinelX Security Alert",
                "text": message,
                "markdown": True,
            }],
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(webhook_url, json=card, timeout=10)
            return {
                "channel": "teams",
                "status": "sent" if resp.status_code == 200 else "error",
                "http_status": resp.status_code,
            }
    except Exception as e:
        logger.error(f"Teams send failed: {e}")
        return {"channel": "teams", "status": "error", "error": str(e)}


CHANNEL_SENDERS = {
    NotificationChannel.email: lambda msg, subj: send_email(subj, msg),
    NotificationChannel.slack: lambda msg, subj: send_slack(msg),
    NotificationChannel.telegram: lambda msg, subj: send_telegram(msg),
    NotificationChannel.discord: lambda msg, subj: send_discord(msg),
    NotificationChannel.teams: lambda msg, subj: send_teams(msg),
}


# ─────────────────────────── Notification Manager ─────────────────────────────

async def notify(
    subject: str,
    message: str,
    severity: str = "medium",
    channels: Optional[List[NotificationChannel]] = None,
) -> List[Dict[str, Any]]:
    """
    Send a notification across appropriate channels based on severity routing.

    Args:
        subject: Alert/incident title
        message: Full message body
        severity: Severity level for routing (critical/high/medium/low/info)
        channels: Override automatic routing with specific channels
    """
    target_channels = channels or DEFAULT_ROUTING.get(severity, [])

    if not target_channels:
        return [{"status": "skipped", "reason": f"No channels configured for severity '{severity}'"}]

    tasks = []
    for channel in target_channels:
        sender = CHANNEL_SENDERS.get(channel)
        if sender:
            tasks.append(sender(message, subject))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    return [
        r if isinstance(r, dict) else {"status": "error", "error": str(r)}
        for r in results
    ]


async def notify_alert(alert_data: dict) -> List[Dict[str, Any]]:
    """Send formatted alert notification."""
    severity = alert_data.get("severity", "medium")
    title = alert_data.get("title", "Security Alert")
    hostname = alert_data.get("hostname", "Unknown")
    source_ip = alert_data.get("source_ip", "Unknown")
    mitre = alert_data.get("mitre_technique", "N/A")

    message = (
        f"🚨 *SentinelX Alert*\n\n"
        f"*Alert:* {title}\n"
        f"*Severity:* {severity.upper()}\n"
        f"*Host:* {hostname}\n"
        f"*Source IP:* {source_ip}\n"
        f"*MITRE:* {mitre}\n"
        f"*Time:* {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )

    return await notify(title, message, severity)


async def notify_incident(incident_data: dict) -> List[Dict[str, Any]]:
    """Send formatted incident notification."""
    severity = incident_data.get("severity", "medium")
    title = incident_data.get("title", "Security Incident")
    status = incident_data.get("status", "open")
    priority = incident_data.get("priority", 3)

    priority_label = {1: "P1 — CRITICAL", 2: "P2 — HIGH", 3: "P3 — MEDIUM", 4: "P4 — LOW"}.get(priority, f"P{priority}")

    message = (
        f"🔴 *SentinelX Incident*\n\n"
        f"*Incident:* {title}\n"
        f"*Priority:* {priority_label}\n"
        f"*Severity:* {severity.upper()}\n"
        f"*Status:* {status}\n"
        f"*Time:* {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )

    return await notify(title, message, severity)


def get_channel_status() -> Dict[str, Any]:
    """Return the configuration status of all notification channels."""
    return {
        "email": {
            "configured": all([settings.SMTP_HOST, settings.SMTP_USER, settings.SMTP_PASS]),
            "host": settings.SMTP_HOST,
        },
        "slack": {
            "configured": bool(settings.SLACK_WEBHOOK_URL),
        },
        "telegram": {
            "configured": bool(settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID),
        },
        "discord": {
            "configured": bool(getattr(settings, "DISCORD_WEBHOOK_URL", None)),
        },
        "teams": {
            "configured": bool(getattr(settings, "TEAMS_WEBHOOK_URL", None)),
        },
        "routing": DEFAULT_ROUTING,
    }
