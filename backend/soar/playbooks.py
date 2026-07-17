"""
SOAR Engine — Automated Security Orchestration, Automation and Response.
Executes playbooks in response to alerts/incidents.
"""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from backend.models import Playbook, PlaybookExecution, PlaybookStatus, Alert, Incident, User
import asyncio
import httpx


# ─────────────── Action Handlers ──────────────────────────────────────────────

async def action_block_ip(params: dict) -> dict:
    ip = params.get("ip")
    return {"action": "block_ip", "ip": ip, "status": "simulated", "message": f"IP {ip} would be blocked at firewall"}


async def action_disable_user(params: dict) -> dict:
    user = params.get("username")
    return {"action": "disable_user", "user": user, "status": "simulated", "message": f"User {user} would be disabled in AD/LDAP"}


async def action_isolate_endpoint(params: dict) -> dict:
    hostname = params.get("hostname")
    return {"action": "isolate_endpoint", "hostname": hostname, "status": "simulated", "message": f"Endpoint {hostname} would be network-isolated"}


async def action_kill_process(params: dict) -> dict:
    process = params.get("process_name")
    hostname = params.get("hostname")
    return {"action": "kill_process", "process": process, "hostname": hostname, "status": "simulated", "message": f"Process {process} would be killed on {hostname}"}


async def action_send_slack(params: dict) -> dict:
    from backend.config import settings
    message = params.get("message", "SentinelX Alert")
    
    if settings.SLACK_WEBHOOK_URL:
        async with httpx.AsyncClient() as client:
            resp = await client.post(settings.SLACK_WEBHOOK_URL, json={"text": message}, timeout=10)
            return {"action": "send_slack", "status": "sent", "response": resp.status_code}
    return {"action": "send_slack", "status": "simulated", "message": "Slack not configured"}


async def action_send_telegram(params: dict) -> dict:
    from backend.config import settings
    message = params.get("message", "SentinelX Alert")
    
    if settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID:
        async with httpx.AsyncClient() as client:
            url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
            resp = await client.post(url, json={"chat_id": settings.TELEGRAM_CHAT_ID, "text": message}, timeout=10)
            return {"action": "send_telegram", "status": "sent"}
    return {"action": "send_telegram", "status": "simulated", "message": "Telegram not configured"}


async def action_send_email(params: dict) -> dict:
    return {"action": "send_email", "status": "simulated", "message": "Email notification would be sent"}


async def action_open_ticket(params: dict) -> dict:
    title = params.get("title", "Security Alert")
    return {"action": "open_ticket", "status": "simulated", "ticket_id": f"TKT-{int(datetime.now().timestamp())}", "title": title}


async def action_restart_service(params: dict) -> dict:
    service = params.get("service_name")
    hostname = params.get("hostname")
    return {"action": "restart_service", "service": service, "hostname": hostname, "status": "simulated"}


async def action_collect_memory(params: dict) -> dict:
    hostname = params.get("hostname")
    return {"action": "collect_memory", "hostname": hostname, "status": "simulated", "message": f"Memory dump would be collected from {hostname}"}


ACTION_MAP = {
    "block_ip": action_block_ip,
    "disable_user": action_disable_user,
    "isolate_endpoint": action_isolate_endpoint,
    "kill_process": action_kill_process,
    "send_slack": action_send_slack,
    "send_telegram": action_send_telegram,
    "send_email": action_send_email,
    "open_ticket": action_open_ticket,
    "restart_service": action_restart_service,
    "collect_memory": action_collect_memory,
}


# ─────────────── Playbook Runner ──────────────────────────────────────────────

async def execute_playbook(
    playbook: Playbook,
    db: AsyncSession,
    alert: Optional[Alert] = None,
    incident: Optional[Incident] = None,
    executed_by: Optional[str] = None
) -> PlaybookExecution:
    
    execution = PlaybookExecution(
        playbook_id=playbook.id,
        alert_id=alert.id if alert else None,
        incident_id=incident.id if incident else None,
        status=PlaybookStatus.running,
        executed_by=executed_by,
        results=[]
    )
    db.add(execution)
    await db.flush()
    
    results = []
    all_success = True
    
    for action_def in (playbook.actions or []):
        action_type = action_def.get("type")
        params = dict(action_def.get("params", {}))
        
        # Inject context from alert/incident
        if alert:
            params.setdefault("ip", alert.source_ip)
            params.setdefault("hostname", alert.hostname)
            params.setdefault("username", alert.user)
            params.setdefault("title", alert.title)
            params.setdefault("message", f"🚨 SentinelX Alert: {alert.title}\nSeverity: {alert.severity.value}\nHost: {alert.hostname}")
        
        handler = ACTION_MAP.get(action_type)
        if handler:
            try:
                result = await handler(params)
                results.append({"action": action_type, "result": result, "success": True})
            except Exception as e:
                results.append({"action": action_type, "error": str(e), "success": False})
                all_success = False
        else:
            results.append({"action": action_type, "error": "Unknown action", "success": False})
            all_success = False
    
    execution.results = results  # type: ignore
    execution.status = PlaybookStatus.completed if all_success else PlaybookStatus.failed  # type: ignore
    execution.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)  # type: ignore
    
    # Update playbook stats
    playbook.run_count = (playbook.run_count or 0) + 1  # type: ignore
    playbook.last_run = datetime.now(timezone.utc).replace(tzinfo=None)  # type: ignore
    
    await db.flush()
    return execution


# Default playbooks to seed
DEFAULT_PLAYBOOKS = [
    {
        "name": "Critical Alert Auto-Response",
        "description": "Automatically block IP and notify SOC team for critical alerts",
        "trigger_severity": "critical",
        "trigger_type": "alert",
        "actions": [
            {"type": "block_ip", "params": {}},
            {"type": "send_slack", "params": {"message": "🚨 CRITICAL ALERT detected by SentinelX"}},
            {"type": "open_ticket", "params": {}}
        ]
    },
    {
        "name": "Brute Force Response",
        "description": "Block attacker IP and lock the targeted account",
        "trigger_severity": "high",
        "trigger_type": "brute_force",
        "actions": [
            {"type": "block_ip", "params": {}},
            {"type": "disable_user", "params": {}},
            {"type": "send_email", "params": {}},
            {"type": "open_ticket", "params": {"title": "Brute Force Attack Detected"}}
        ]
    },
    {
        "name": "Endpoint Isolation Playbook",
        "description": "Isolate endpoint, collect memory, and notify team",
        "trigger_severity": "critical",
        "trigger_type": "malware",
        "actions": [
            {"type": "isolate_endpoint", "params": {}},
            {"type": "collect_memory", "params": {}},
            {"type": "send_slack", "params": {"message": "🔒 Endpoint isolated by SentinelX SOAR"}},
            {"type": "open_ticket", "params": {"title": "Endpoint Isolation - Malware"}}
        ]
    },
    {
        "name": "Ransomware Emergency Response",
        "description": "Full emergency response for ransomware detection",
        "trigger_severity": "critical",
        "trigger_type": "ransomware",
        "actions": [
            {"type": "isolate_endpoint", "params": {}},
            {"type": "block_ip", "params": {}},
            {"type": "collect_memory", "params": {}},
            {"type": "send_slack", "params": {"message": "🔥 RANSOMWARE DETECTED — Emergency response activated"}},
            {"type": "send_telegram", "params": {"message": "🔥 RANSOMWARE ALERT — SentinelX SOAR"}},
            {"type": "send_email", "params": {}},
            {"type": "open_ticket", "params": {"title": "RANSOMWARE INCIDENT"}}
        ]
    },
]
