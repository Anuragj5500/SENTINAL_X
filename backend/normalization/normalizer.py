"""
Log Normalization Engine — converts diverse log formats into a unified schema.
"""
from typing import Dict, Any


NORMALIZED_SCHEMA = {
    "timestamp": None,
    "hostname": None,
    "user": None,
    "event_type": None,
    "source_ip": None,
    "destination_ip": None,
    "severity": "info",
    "event_id": None,
    "command": None,
    "process_name": None,
    "file_path": None,
    "hash_value": None,
    "status": None,
    "source_platform": None,
    "source": None,
    "tags": [],
}

# Windows Event ID mapping
WINDOWS_EVENT_MAP = {
    "4624": {"event_type": "authentication_success", "severity": "info"},
    "4625": {"event_type": "authentication_failure", "severity": "medium"},
    "4648": {"event_type": "explicit_credentials_logon", "severity": "high"},
    "4656": {"event_type": "object_access", "severity": "low"},
    "4688": {"event_type": "process_creation", "severity": "info"},
    "4697": {"event_type": "service_installed", "severity": "high"},
    "4698": {"event_type": "scheduled_task_created", "severity": "high"},
    "4720": {"event_type": "user_account_created", "severity": "medium"},
    "4728": {"event_type": "member_added_to_group", "severity": "medium"},
    "4732": {"event_type": "member_added_to_local_group", "severity": "medium"},
    "4740": {"event_type": "account_locked", "severity": "medium"},
    "4768": {"event_type": "kerberos_ticket_request", "severity": "info"},
    "4769": {"event_type": "kerberos_service_ticket", "severity": "info"},
    "4776": {"event_type": "ntlm_authentication", "severity": "medium"},
    "4798": {"event_type": "local_group_enumeration", "severity": "medium"},
    "4799": {"event_type": "local_group_membership_enumeration", "severity": "medium"},
    "5140": {"event_type": "network_share_access", "severity": "medium"},
    "7045": {"event_type": "new_service_installed", "severity": "high"},
}


def normalize_log(raw: dict) -> dict:
    """Normalize a raw log dict into the unified schema."""
    normalized = dict(NORMALIZED_SCHEMA)
    
    # Map direct fields
    normalized["timestamp"] = str(raw.get("timestamp", ""))
    normalized["hostname"] = raw.get("hostname")
    normalized["user"] = raw.get("user")
    normalized["source_ip"] = raw.get("source_ip")
    normalized["destination_ip"] = raw.get("destination_ip")
    normalized["severity"] = raw.get("severity", "info")
    normalized["command"] = raw.get("command")
    normalized["process_name"] = raw.get("process_name")
    normalized["file_path"] = raw.get("file_path")
    normalized["hash_value"] = raw.get("hash_value")
    normalized["status"] = raw.get("status")
    normalized["source_platform"] = raw.get("source", "unknown")
    normalized["source"] = raw.get("source")
    
    # Apply Windows event ID enrichment
    event_id = str(raw.get("event_id", ""))
    if event_id in WINDOWS_EVENT_MAP:
        mapping = WINDOWS_EVENT_MAP[event_id]
        normalized["event_type"] = mapping["event_type"]
        if normalized["severity"] == "info":
            normalized["severity"] = mapping["severity"]
    else:
        normalized["event_type"] = raw.get("event_type", "unknown")
    
    normalized["event_id"] = event_id
    
    # Tag enrichment
    tags = []
    if raw.get("command") and any(kw in str(raw.get("command", "")).lower() for kw in ["powershell", "cmd", "bash"]):
        tags.append("shell_execution")
    if event_id in ["4625", "4740"] or normalized["event_type"] == "authentication_failure":
        tags.append("auth_failure")
    if event_id in ["4688"] or normalized["event_type"] == "process_creation":
        tags.append("process_creation")
    if raw.get("user") and "admin" in str(raw.get("user", "")).lower():
        tags.append("admin_activity")
    normalized["tags"] = tags
    
    return normalized
