"""
SentinelX — Enterprise SIEM, Threat Detection & SOAR Platform
FastAPI Backend — Main Application Entry Point
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time
import uuid
import typing

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from backend.config import settings
from backend.database import init_db, AsyncSessionLocal
from backend.models import UserRole

# ─────────────── API Routers ──────────────────────────────────────────────────
from backend.api.auth import router as auth_router
from backend.api.dashboard import router as dashboard_router
from backend.api.alerts import router as alerts_router
from backend.api.incidents import router as incidents_router
from backend.api.assets import router as assets_router
from backend.api.logs import router as logs_router
from backend.api.threat_intel import router as threat_intel_router
from backend.api.soar import router as soar_router
from backend.api.admin import router as admin_router
from backend.api.hunt import router as hunt_router
from backend.api.rules import router as rules_router
from backend.api.vulnerabilities import router as vulns_router
from backend.api.reports import router as reports_router
from backend.api.compliance import router as compliance_router
from backend.api.notifications import router as notifications_router
from backend.api.cloud import router as cloud_router
from backend.api.websocket import router as websocket_router


# ─────────────── Startup / Shutdown ───────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("SentinelX SIEM starting up...")
    
    # Initialize database
    await init_db()
    print("Database initialized")
    
    # Seed default data
    await seed_defaults()
    print("Default data seeded")
    
    yield
    
    print("SentinelX shutting down")


async def seed_defaults():
    """Seed default admin user, detection rules, and playbooks."""
    from sqlalchemy import select
    from backend.models import User, DetectionRule, Playbook, Severity
    from backend.auth.jwt import hash_password
    from backend.soar.playbooks import DEFAULT_PLAYBOOKS
    import json, os
    
    async with AsyncSessionLocal() as db:
        # Create super admin if not exists
        # Create super admin if not exists
        result = await db.execute(select(User).where(User.username == "admin"))
        if not result.scalar_one_or_none():
            admin = User(
                username="admin",
                email="admin@sentinelx.local",
                full_name="Super Administrator",
                hashed_password=hash_password("SentinelX@2024!"),
                role=UserRole.super_admin,
                is_active=True
            )
            db.add(admin)
            await db.flush()
            
        # Also create demo analyst
        result = await db.execute(select(User).where(User.username == "analyst"))
        if not result.scalar_one_or_none():
            analyst = User(
                username="analyst",
                email="analyst@sentinelx.local",
                full_name="SOC Analyst",
                hashed_password=hash_password("Analyst@2024!"),
                role=UserRole.analyst,
                is_active=True
            )
            db.add(analyst)
            await db.flush()
        
        # Seed detection rules from default_rules.json
        rules_count = (await db.execute(select(DetectionRule).limit(1))).scalar_one_or_none()
        if not rules_count:
            rules_file = os.path.join(os.path.dirname(__file__), "detection", "rules", "default_rules.json")
            with open(rules_file) as f:
                rules = json.load(f)
            for rule_data in rules:
                rule = DetectionRule(
                    id=rule_data["id"],
                    name=rule_data["name"],
                    description=rule_data["description"],
                    rule_type=rule_data["rule_type"],
                    severity=Severity(rule_data["severity"]),
                    enabled=rule_data["enabled"],
                    logic=rule_data["logic"],
                    mitre_technique=rule_data.get("mitre_technique"),
                    mitre_tactic=rule_data.get("mitre_tactic"),
                    tags=rule_data.get("tags", [])
                )
                db.add(rule)
            await db.flush()
        
        # Seed playbooks
        pb_count = (await db.execute(select(Playbook).limit(1))).scalar_one_or_none()
        if not pb_count:
            for pb_data in DEFAULT_PLAYBOOKS:
                pb = Playbook(
                    name=pb_data["name"],
                    description=pb_data["description"],
                    trigger_severity=Severity(pb_data["trigger_severity"]),
                    trigger_type=pb_data["trigger_type"],
                    actions=pb_data["actions"],
                    enabled=True
                )
                db.add(pb)
            await db.flush()
        
        await db.commit()


# ─────────────── FastAPI App ───────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT_DEFAULT])

app = FastAPI(
    title="SentinelX SIEM API",
    description="Enterprise Security Information and Event Management Platform",
    version=settings.APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, typing.cast(typing.Any, _rate_limit_exceeded_handler))


# ─────────────── Middleware ───────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers, request ID, and process time to every response."""
    request_id = str(uuid.uuid4())
    start_time = time.time()
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(round(process_time * 1000, 2))
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Powered-By"] = "SentinelX"
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


# ─────────────── Routers ──────────────────────────────────────────────────────

API_PREFIX = "/api/v1"

app.include_router(auth_router, prefix=API_PREFIX)
app.include_router(dashboard_router, prefix=API_PREFIX)
app.include_router(alerts_router, prefix=API_PREFIX)
app.include_router(incidents_router, prefix=API_PREFIX)
app.include_router(assets_router, prefix=API_PREFIX)
app.include_router(logs_router, prefix=API_PREFIX)
app.include_router(threat_intel_router, prefix=API_PREFIX)
app.include_router(soar_router, prefix=API_PREFIX)
app.include_router(admin_router, prefix=API_PREFIX)
app.include_router(hunt_router, prefix=API_PREFIX)
app.include_router(rules_router, prefix=API_PREFIX)
app.include_router(vulns_router, prefix=API_PREFIX)
app.include_router(reports_router, prefix=API_PREFIX)
app.include_router(compliance_router, prefix=API_PREFIX)
app.include_router(notifications_router, prefix=API_PREFIX)
app.include_router(cloud_router, prefix=API_PREFIX)
app.include_router(websocket_router)


# ─────────────── Health Check ─────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "operational",
        "service": "SentinelX SIEM",
        "version": settings.APP_VERSION
    }


@app.get("/")
async def root():
    return {
        "message": "SentinelX SIEM API",
        "docs": "/api/docs",
        "version": settings.APP_VERSION
    }
