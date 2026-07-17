from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, Float, Text, JSON,
    ForeignKey, Enum as SAEnum
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from backend.database import Base
import enum
import uuid


def generate_uuid():
    return str(uuid.uuid4())


# ─────────────────────────────── Enums ────────────────────────────────────────

class UserRole(str, enum.Enum):
    super_admin = "super_admin"
    soc_manager = "soc_manager"
    analyst = "analyst"
    threat_hunter = "threat_hunter"
    responder = "responder"
    auditor = "auditor"
    readonly = "readonly"


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class AlertStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    investigating = "investigating"
    false_positive = "false_positive"
    resolved = "resolved"


class IncidentStatus(str, enum.Enum):
    open = "open"
    assigned = "assigned"
    investigating = "investigating"
    containment = "containment"
    recovery = "recovery"
    resolved = "resolved"
    closed = "closed"


class AssetCriticality(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class PlaybookStatus(str, enum.Enum):
    idle = "idle"
    running = "running"
    completed = "completed"
    failed = "failed"


# ─────────────────────────────── Models ───────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=generate_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True, nullable=False)
    full_name = Column(String(128))
    hashed_password = Column(String(256), nullable=False)
    role = Column(SAEnum(UserRole), default=UserRole.analyst)
    is_active = Column(Boolean, default=True)
    is_mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(64), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    audit_logs = relationship("AuditLog", back_populates="user", lazy="select")
    incidents = relationship("Incident", back_populates="owner", lazy="select")
    alerts = relationship("Alert", back_populates="assigned_to_user", lazy="select")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String, primary_key=True, default=generate_uuid)
    hostname = Column(String(128), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    mac_address = Column(String(17))
    os_type = Column(String(64))
    os_version = Column(String(128))
    criticality = Column(SAEnum(AssetCriticality), default=AssetCriticality.medium)
    department = Column(String(64))
    owner = Column(String(128))
    tags = Column(JSON, default=list)
    installed_software = Column(JSON, default=list)
    antivirus_status = Column(String(32), default="unknown")
    agent_installed = Column(Boolean, default=False)
    last_seen = Column(DateTime, nullable=True)
    risk_score = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class Log(Base):
    __tablename__ = "logs"

    id = Column(String, primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, nullable=False, index=True)
    hostname = Column(String(128), index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45))
    user = Column(String(128), index=True)
    event_type = Column(String(64), index=True)
    event_id = Column(String(32))
    source = Column(String(64))     # windows, linux, firewall, etc.
    severity = Column(SAEnum(Severity), default=Severity.info)
    command = Column(Text, nullable=True)
    process_name = Column(String(128))
    file_path = Column(Text, nullable=True)
    hash_value = Column(String(64))
    status = Column(String(32))
    raw_log = Column(Text)
    normalized = Column(JSON, default=dict)
    created_at = Column(DateTime, server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, default=generate_uuid)
    title = Column(String(256), nullable=False)
    description = Column(Text)
    severity = Column(SAEnum(Severity), nullable=False)
    status = Column(SAEnum(AlertStatus), default=AlertStatus.open)
    source = Column(String(64))
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    hostname = Column(String(128))
    user = Column(String(128))
    process_name = Column(String(128))
    command = Column(Text)
    mitre_technique = Column(String(32))
    mitre_tactic = Column(String(64))
    mitre_sub_technique = Column(String(64))
    rule_id = Column(String, ForeignKey("detection_rules.id"), nullable=True)
    log_id = Column(String, ForeignKey("logs.id"), nullable=True)
    assigned_to = Column(String, ForeignKey("users.id"), nullable=True)
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True)
    enrichment_data = Column(JSON, default=dict)
    ai_analysis = Column(Text, nullable=True)
    risk_score = Column(Float, default=0.0)
    false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now(), index=True)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    assigned_to_user = relationship("User", back_populates="alerts", foreign_keys=[assigned_to])
    rule = relationship("DetectionRule", back_populates="alerts")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=generate_uuid)
    title = Column(String(256), nullable=False)
    description = Column(Text)
    severity = Column(SAEnum(Severity), nullable=False)
    priority = Column(Integer, default=3)  # 1=critical, 2=high, 3=medium, 4=low
    status = Column(SAEnum(IncidentStatus), default=IncidentStatus.open)
    owner_id = Column(String, ForeignKey("users.id"), nullable=True)
    tags = Column(JSON, default=list)
    timeline = Column(JSON, default=list)
    evidence = Column(JSON, default=list)
    affected_assets = Column(JSON, default=list)
    iocs = Column(JSON, default=list)        # Indicators of Compromise
    mitre_techniques = Column(JSON, default=list)
    ai_summary = Column(Text, nullable=True)
    resolution_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), index=True)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    resolved_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)

    owner = relationship("User", back_populates="incidents")
    alerts = relationship("Alert", primaryjoin="Alert.incident_id == Incident.id",
                          foreign_keys="Alert.incident_id", lazy="select")
    comments = relationship("IncidentComment", back_populates="incident", lazy="select")


class IncidentComment(Base):
    __tablename__ = "incident_comments"

    id = Column(String, primary_key=True, default=generate_uuid)
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    incident = relationship("Incident", back_populates="comments")
    user = relationship("User")


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(256), nullable=False)
    description = Column(Text)
    rule_type = Column(String(32))    # sigma, yara, custom, ml
    severity = Column(SAEnum(Severity), nullable=False)
    enabled = Column(Boolean, default=True)
    logic = Column(JSON, default=dict)   # Rule conditions
    mitre_technique = Column(String(32))
    mitre_tactic = Column(String(64))
    tags = Column(JSON, default=list)
    trigger_count = Column(Integer, default=0)
    false_positive_count = Column(Integer, default=0)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    alerts = relationship("Alert", back_populates="rule")


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(256), nullable=False)
    description = Column(Text)
    trigger_severity = Column(SAEnum(Severity))
    trigger_type = Column(String(64))
    actions = Column(JSON, default=list)
    enabled = Column(Boolean, default=True)
    run_count = Column(Integer, default=0)
    last_run = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id = Column(String, primary_key=True, default=generate_uuid)
    playbook_id = Column(String, ForeignKey("playbooks.id"))
    alert_id = Column(String, ForeignKey("alerts.id"), nullable=True)
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True)
    status = Column(SAEnum(PlaybookStatus), default=PlaybookStatus.running)
    results = Column(JSON, default=list)
    executed_by = Column(String, ForeignKey("users.id"), nullable=True)
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)


class ThreatIntelFeed(Base):
    __tablename__ = "threat_intel_feeds"

    id = Column(String, primary_key=True, default=generate_uuid)
    ioc_value = Column(String(512), nullable=False, index=True)
    ioc_type = Column(String(32))     # ip, domain, hash, url
    threat_type = Column(String(64))
    confidence = Column(Integer, default=50)
    source = Column(String(64))       # virustotal, abuseipdb, otx
    raw_data = Column(JSON, default=dict)
    first_seen = Column(DateTime, server_default=func.now())
    last_seen = Column(DateTime, server_default=func.now())
    is_active = Column(Boolean, default=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String(128), nullable=False)
    resource_type = Column(String(64))
    resource_id = Column(String)
    details = Column(JSON, default=dict)
    ip_address = Column(String(45))
    user_agent = Column(String(256))
    created_at = Column(DateTime, server_default=func.now(), index=True)

    user = relationship("User", back_populates="audit_logs")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, default=generate_uuid)
    asset_id = Column(String, ForeignKey("assets.id"), nullable=True)
    cve_id = Column(String(32), index=True)
    title = Column(String(256))
    description = Column(Text)
    severity = Column(SAEnum(Severity))
    cvss_score = Column(Float, default=0.0)
    affected_software = Column(String(256))
    remediation = Column(Text)
    status = Column(String(32), default="open")
    discovered_at = Column(DateTime, server_default=func.now())


class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=generate_uuid)
    title = Column(String(256), nullable=False)
    report_type = Column(String(64))    # incident, executive, compliance, ioc
    generated_by = Column(String, ForeignKey("users.id"), nullable=True)
    params = Column(JSON, default=dict)
    file_path = Column(String(512), nullable=True)
    status = Column(String(32), default="pending")
    created_at = Column(DateTime, server_default=func.now())


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(128), nullable=False)
    key_hash = Column(String(256), nullable=False, index=True)
    key_prefix = Column(String(12), nullable=False)  # First 8 chars for identification
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    scopes = Column(JSON, default=list)  # e.g., ["logs:write", "alerts:read"]
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    user = relationship("User")


class CloudEvent(Base):
    __tablename__ = "cloud_events"

    id = Column(String, primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, nullable=False, index=True)
    provider = Column(String(16), index=True)  # aws, azure, gcp
    region = Column(String(32))
    service = Column(String(64))
    event_type = Column(String(128), index=True)
    severity = Column(SAEnum(Severity), default=Severity.info)
    user = Column(String(128))
    source_ip = Column(String(45))
    resource_id = Column(String(256))
    description = Column(Text)
    raw_data = Column(JSON, default=dict)
    risk_score = Column(Float, default=0.0)
    created_at = Column(DateTime, server_default=func.now())

