from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, EmailStr, Field
from backend.models import UserRole, Severity, AlertStatus, IncidentStatus, AssetCriticality


# ─────────────── Auth ───────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    full_name: Optional[str] = None
    password: str = Field(..., min_length=8)
    role: UserRole = UserRole.analyst

class UserLogin(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None

class UserOut(BaseModel):
    id: str
    username: str
    email: str
    full_name: Optional[str]
    role: UserRole
    is_active: bool
    is_mfa_enabled: bool
    last_login: Optional[datetime]
    created_at: datetime
    model_config = {"from_attributes": True}

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut

class RefreshRequest(BaseModel):
    refresh_token: str

class MFASetupResponse(BaseModel):
    secret: str
    qr_uri: str

class MFAVerify(BaseModel):
    totp_code: str

class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


# ─────────────── Asset ──────────────────────────────────────────────────────

class AssetCreate(BaseModel):
    hostname: str
    ip_address: str
    mac_address: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    criticality: AssetCriticality = AssetCriticality.medium
    department: Optional[str] = None
    owner: Optional[str] = None
    tags: List[str] = []

class AssetOut(BaseModel):
    id: str
    hostname: str
    ip_address: str
    mac_address: Optional[str]
    os_type: Optional[str]
    os_version: Optional[str]
    criticality: AssetCriticality
    department: Optional[str]
    owner: Optional[str]
    tags: List[str]
    antivirus_status: str
    agent_installed: bool
    last_seen: Optional[datetime]
    risk_score: float
    is_active: bool
    created_at: datetime
    model_config = {"from_attributes": True}


# ─────────────── Log ────────────────────────────────────────────────────────

class LogIngest(BaseModel):
    timestamp: datetime
    hostname: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    event_type: str
    event_id: Optional[str] = None
    source: str
    severity: Severity = Severity.info
    command: Optional[str] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    hash_value: Optional[str] = None
    status: Optional[str] = None
    raw_log: Optional[str] = None

class LogOut(BaseModel):
    id: str
    timestamp: datetime
    hostname: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    user: Optional[str]
    event_type: str
    event_id: Optional[str]
    source: str
    severity: Severity
    command: Optional[str]
    process_name: Optional[str]
    created_at: datetime
    model_config = {"from_attributes": True}


# ─────────────── Alert ──────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id: str
    title: str
    description: Optional[str]
    severity: Severity
    status: AlertStatus
    source: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    hostname: Optional[str]
    user: Optional[str]
    process_name: Optional[str]
    command: Optional[str]
    mitre_technique: Optional[str]
    mitre_tactic: Optional[str]
    risk_score: float
    enrichment_data: dict
    ai_analysis: Optional[str]
    incident_id: Optional[str]
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}

class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    assigned_to: Optional[str] = None
    incident_id: Optional[str] = None
    false_positive: Optional[bool] = None


# ─────────────── Incident ───────────────────────────────────────────────────

class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: Severity
    priority: int = Field(3, ge=1, le=4)
    tags: List[str] = []
    affected_assets: List[str] = []

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[Severity] = None
    priority: Optional[int] = None
    status: Optional[IncidentStatus] = None
    owner_id: Optional[str] = None
    tags: Optional[List[str]] = None
    resolution_notes: Optional[str] = None

class IncidentCommentCreate(BaseModel):
    content: str

class IncidentOut(BaseModel):
    id: str
    title: str
    description: Optional[str]
    severity: Severity
    priority: int
    status: IncidentStatus
    owner_id: Optional[str]
    tags: List[str]
    timeline: List[dict]
    evidence: List[Any]
    affected_assets: List[str]
    iocs: List[str]
    mitre_techniques: List[str]
    ai_summary: Optional[str]
    resolution_notes: Optional[str]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]
    model_config = {"from_attributes": True}


# ─────────────── Detection Rule ─────────────────────────────────────────────

class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    rule_type: str = "custom"
    severity: Severity
    logic: dict
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    tags: List[str] = []

class RuleOut(BaseModel):
    id: str
    name: str
    description: Optional[str]
    rule_type: str
    severity: Severity
    enabled: bool
    logic: dict
    mitre_technique: Optional[str]
    mitre_tactic: Optional[str]
    tags: List[str]
    trigger_count: int
    false_positive_count: int
    created_at: datetime
    model_config = {"from_attributes": True}


# ─────────────── Playbook ────────────────────────────────────────────────────

class PlaybookOut(BaseModel):
    id: str
    name: str
    description: Optional[str]
    trigger_severity: Optional[Severity]
    trigger_type: Optional[str]
    actions: List[dict]
    enabled: bool
    run_count: int
    last_run: Optional[datetime]
    created_at: datetime
    model_config = {"from_attributes": True}

class PlaybookRunRequest(BaseModel):
    alert_id: Optional[str] = None
    incident_id: Optional[str] = None


# ─────────────── Dashboard ──────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    total_incidents: int
    open_incidents: int
    total_assets: int
    online_assets: int
    events_today: int
    mean_time_to_detect: float
    mean_time_to_respond: float
    top_attackers: List[dict]
    alerts_by_severity: dict
    alerts_by_hour: List[dict]
    mitre_heatmap: List[dict]
    recent_alerts: List[dict]


# ─────────────── Pagination ──────────────────────────────────────────────────

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    pages: int
