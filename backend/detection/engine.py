"""
Detection Engine — runs all rules against incoming logs and generates alerts.
Supports: signature matching, threshold detection, IOC matching.
"""
import json
import os
from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from backend.models import Log, Alert, DetectionRule, ThreatIntelFeed, Severity
from backend.api.websocket import manager as ws_manager

# Cache rules in memory
_rule_cache: list = []
_rule_cache_time: Optional[datetime] = None
CACHE_TTL = 300  # 5 minutes

# Brute force tracker: {key: [timestamps]}
_brute_force_tracker: dict = {}

RULES_FILE = os.path.join(os.path.dirname(__file__), "rules", "default_rules.json")


def load_default_rules() -> list:
    global _rule_cache, _rule_cache_time
    now = datetime.now(timezone.utc)
    
    if _rule_cache and _rule_cache_time and (now - _rule_cache_time).seconds < CACHE_TTL:
        return _rule_cache
    
    try:
        with open(RULES_FILE, "r") as f:
            _rule_cache = json.load(f)
            _rule_cache_time = now
            return _rule_cache
    except Exception:
        return []


def _match_signature(rule: dict, log: Log) -> bool:
    logic = rule.get("logic", {})
    
    # Check event_id
    if "event_id_any" in logic:
        if log.event_id not in logic["event_id_any"]:
            return False
    
    # Check single event_type
    if "event_type" in logic and not ("threshold" in logic):
        if log.event_type != logic["event_type"]:
            return False
    
    # Check process name
    if "process_name_any" in logic:
        proc = (log.process_name or "").lower()
        if not any(p.lower() in proc for p in logic["process_name_any"]):
            # Also check if there's an "or_command_contains"
            if "or_command_contains" not in logic:
                return False
    
    # Check command contains
    if "contains_any" in logic:
        cmd = (log.command or "").lower()
        if not any(kw.lower() in cmd for kw in logic["contains_any"]):
            return False
    
    if "or_command_contains" in logic:
        cmd = (log.command or "").lower()
        proc = (log.process_name or "").lower()
        matched = any(kw.lower() in cmd or kw.lower() in proc for kw in logic["or_command_contains"])
        if "process_name_any" in logic:
            proc_match = any(p.lower() in proc for p in logic.get("process_name_any", []))
            if not (proc_match or matched):
                return False
        elif not matched:
            return False
    
    if "command_contains_any" in logic:
        cmd = (log.command or "").lower()
        if not any(kw.lower() in cmd for kw in logic["command_contains_any"]):
            return False
    
    # Check file path
    if "file_path_contains_any" in logic:
        fp = (log.file_path or "").lower()
        if not any(kw.lower() in fp for kw in logic["file_path_contains_any"]):
            return False
    
    return True


def _match_threshold(rule: dict, log: Log) -> bool:
    logic = rule.get("logic", {})
    if log.event_type != logic.get("event_type"):
        return False
    
    group_by = logic.get("group_by", "source_ip")
    key_value = getattr(log, group_by, None)
    if not key_value:
        return False
    
    tracker_key = f"{rule['id']}:{key_value}"
    now = datetime.now(timezone.utc)
    window = timedelta(seconds=logic.get("window_seconds", 120))
    threshold = logic.get("threshold", 5)
    
    if tracker_key not in _brute_force_tracker:
        _brute_force_tracker[tracker_key] = []
    
    # Trim old events
    _brute_force_tracker[tracker_key] = [
        t for t in _brute_force_tracker[tracker_key]
        if now - t < window
    ]
    _brute_force_tracker[tracker_key].append(now)
    
    return len(_brute_force_tracker[tracker_key]) >= threshold


async def check_ioc_match(log: Log, db: AsyncSession) -> tuple[bool, dict]:
    """Check if any field matches known IOCs in threat intel feed."""
    values_to_check = [log.source_ip, log.destination_ip, log.hash_value]
    values_to_check = [v for v in values_to_check if v]
    
    if not values_to_check:
        return False, {}
    
    result = await db.execute(
        select(ThreatIntelFeed).where(
            ThreatIntelFeed.ioc_value.in_(values_to_check)
        ).limit(1)
    )
    match = result.scalar_one_or_none()
    if match:
        return True, {
            "ioc_value": match.ioc_value,
            "ioc_type": match.ioc_type,
            "threat_type": match.threat_type,
            "source": match.source,
            "confidence": match.confidence
        }
    return False, {}


async def run_detection(log: Log, db: AsyncSession):
    """Main detection entry point called for every ingested log."""
    rules = load_default_rules()
    
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        
        matched = False
        rule_type = rule.get("rule_type", "signature")
        
        if rule_type == "threshold":
            matched = _match_threshold(rule, log)
        elif rule_type == "signature":
            matched = _match_signature(rule, log)
        
        if matched:
            alert = Alert(
                title=rule["name"],
                description=rule["description"],
                severity=Severity(rule["severity"]),
                source=log.source,
                source_ip=log.source_ip,
                destination_ip=log.destination_ip,
                hostname=log.hostname,
                user=log.user,
                process_name=log.process_name,
                command=log.command,
                mitre_technique=rule.get("mitre_technique"),
                mitre_tactic=rule.get("mitre_tactic"),
                log_id=log.id,
                risk_score=_calculate_risk(rule["severity"]),
            )
            db.add(alert)
            await db.flush()
            await ws_manager.broadcast({"type": "new_alert"})
    
    # IOC matching
    ioc_matched, ioc_data = await check_ioc_match(log, db)
    if ioc_matched:
        alert = Alert(
            title=f"IOC Match: {ioc_data['ioc_value']}",
            description=f"Known malicious {ioc_data['ioc_type']} detected — {ioc_data['threat_type']}",
            severity=Severity.critical,
            source=log.source,
            source_ip=log.source_ip,
            hostname=log.hostname,
            user=log.user,
            log_id=log.id,
            enrichment_data=ioc_data,
            risk_score=95.0,
        )
        db.add(alert)
        await db.flush()
        await ws_manager.broadcast({"type": "new_alert"})


def _calculate_risk(severity: str) -> float:
    return {"critical": 95.0, "high": 75.0, "medium": 50.0, "low": 25.0, "info": 5.0}.get(severity, 0.0)
