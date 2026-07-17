"""
SentinelX Seed Data Generator
Generates realistic SOC simulation data: assets, logs, alerts, incidents.
Run: python scripts/seed_data.py
"""
import asyncio
import random
import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from faker import Faker
from backend.database import AsyncSessionLocal, init_db
from backend.models import (
    Asset, Log, Alert, Incident, ThreatIntelFeed,
    AssetCriticality, Severity, AlertStatus, IncidentStatus
)

fake = Faker()
random.seed(42)

# ─────────────────────────────────────────────────────────────────────────────

HOSTNAMES = [
    "WIN-DC01", "WIN-WEB01", "WIN-DB01", "WIN-DEV01", "WIN-ADMIN01",
    "LINUX-PROD01", "LINUX-API01", "LINUX-DB02", "LINUX-JUMP01", "MAC-CEO01",
    "WIN-SALES01", "WIN-HR01", "WIN-FINANCE01", "LINUX-MAIL01", "WIN-BACKUP01"
]

DEPARTMENTS = ["IT", "Finance", "HR", "Sales", "Engineering", "Executive", "Security", "Operations"]
OS_TYPES = ["Windows Server 2022", "Windows 11 Pro", "Ubuntu 22.04 LTS", "CentOS 8", "Debian 11", "macOS Ventura"]
CRITICALITY_WEIGHTS = [AssetCriticality.critical, AssetCriticality.high, AssetCriticality.medium, AssetCriticality.low]

SUSPICIOUS_IPS = [
    "185.220.101.55", "91.108.4.223", "45.33.32.156", "103.75.191.12",
    "198.54.117.200", "77.81.230.18", "185.130.44.108", "23.227.38.32"
]

MITRE_ATTACK_SCENARIOS = [
    ("Brute Force Login", Severity.high, "T1110", "Credential Access", "authentication_failure"),
    ("PowerShell Encoded Command", Severity.critical, "T1059.001", "Execution", "process_creation"),
    ("Scheduled Task Created", Severity.high, "T1053.005", "Persistence", "process_creation"),
    ("LSASS Memory Access", Severity.critical, "T1003.001", "Credential Access", "process_creation"),
    ("PsExec Lateral Movement", Severity.critical, "T1021.002", "Lateral Movement", "network_connection"),
    ("New Admin Account", Severity.high, "T1136.001", "Persistence", "user_created"),
    ("Ransomware Extension", Severity.critical, "T1486", "Impact", "file_modification"),
    ("Network Port Scan", Severity.medium, "T1046", "Discovery", "network_connection"),
    ("Service Installation", Severity.medium, "T1543.003", "Persistence", "service_installed"),
    ("DNS Tunneling", Severity.high, "T1048.003", "Exfiltration", "dns_query"),
    ("Token Manipulation", Severity.critical, "T1134", "Privilege Escalation", "process_access"),
    ("Suspicious Cron Job", Severity.medium, "T1053.003", "Persistence", "file_modification"),
    ("Mimikatz Detection", Severity.critical, "T1003.001", "Credential Access", "process_creation"),
    ("Data Staging", Severity.high, "T1074", "Collection", "file_modification"),
    ("C2 Beacon", Severity.critical, "T1071", "Command and Control", "network_connection"),
]

MALICIOUS_IOCS = [
    ("185.220.101.55", "ip", "tor_exit_node", 90),
    ("91.108.4.223", "ip", "c2_server", 95),
    ("45.33.32.156", "ip", "scanner", 75),
    ("44d88612fea8a8f36de82e1278abb02f", "hash", "malware_dropper", 100),
    ("3395856ce81f2b7382dee72602f798b6", "hash", "ransomware", 100),
    ("badactor.tk", "domain", "malware_c2", 95),
    ("evil-payload.ml", "domain", "phishing", 90),
    ("https://malware.ga/payload.exe", "url", "malware_download", 95),
]


async def seed_assets(db) -> list:
    print("  Seeding assets...")
    assets = []
    for hostname in HOSTNAMES:
        asset = Asset(
            hostname=hostname,
            ip_address=fake.ipv4_private(),
            mac_address=fake.mac_address(),
            os_type=random.choice(OS_TYPES),
            os_version="",
            criticality=random.choices(CRITICALITY_WEIGHTS, weights=[1, 2, 4, 3])[0],
            department=random.choice(DEPARTMENTS),
            owner=fake.name(),
            tags=random.sample(["server", "workstation", "critical", "internet-facing", "database", "web"], k=2),
            antivirus_status=random.choice(["active", "active", "active", "outdated", "missing"]),
            agent_installed=random.choice([True, True, False]),
            last_seen=datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 60)),
            risk_score=round(random.uniform(0, 100), 1)
        )
        db.add(asset)
        assets.append(asset)
    await db.flush()
    print(f"    ✓ {len(assets)} assets created")
    return assets


async def seed_threat_intel(db):
    print("  Seeding threat intel IOCs...")
    for ioc_value, ioc_type, threat_type, confidence in MALICIOUS_IOCS:
        feed = ThreatIntelFeed(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            threat_type=threat_type,
            confidence=confidence,
            source="demo_seed",
            first_seen=datetime.now(timezone.utc) - timedelta(days=random.randint(1, 90)),
            last_seen=datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 48))
        )
        db.add(feed)
    await db.flush()
    print(f"    ✓ {len(MALICIOUS_IOCS)} IOCs created")


async def seed_logs_and_alerts(db, assets: list, num_logs: int = 500, num_alerts: int = 200):
    print(f"  Seeding {num_logs} logs and {num_alerts} alerts...")
    
    # Generate logs
    for _ in range(num_logs):
        host = random.choice(assets)
        src_ip = random.choice([fake.ipv4_private(), fake.ipv4_public(), random.choice(SUSPICIOUS_IPS)])
        ts = datetime.now(timezone.utc) - timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        event_types = ["authentication_success", "authentication_failure", "process_creation",
                       "network_connection", "file_modification", "user_created"]
        event_type = random.choice(event_types)
        severity = random.choices(
            [Severity.info, Severity.low, Severity.medium, Severity.high, Severity.critical],
            weights=[40, 25, 20, 10, 5]
        )[0]
        
        log = Log(
            timestamp=ts,
            hostname=host.hostname,
            source_ip=src_ip,
            destination_ip=fake.ipv4_public() if random.random() > 0.5 else None,
            user=random.choice([fake.user_name(), "administrator", "SYSTEM", "root", "admin"]),
            event_type=event_type,
            event_id=str(random.choice([4624, 4625, 4688, 4698, 4720, 4740, 7045])),
            source=random.choice(["windows", "linux", "firewall", "web", "dns"]),
            severity=severity,
            process_name=random.choice(["svchost.exe", "powershell.exe", "cmd.exe", "explorer.exe", None]),
            command=random.choice([
                "powershell.exe -EncodedCommand SGVsbG8gV29ybGQ=",
                "net user hacker /add",
                "schtasks /create /tn 'Update' /tr 'malware.exe'",
                "psexec \\\\server01 cmd.exe",
                None, None, None
            ]),
            raw_log=f"{ts} {host.hostname} {event_type} src={src_ip}",
            normalized={"event_type": event_type}
        )
        db.add(log)
    
    await db.flush()
    
    # Generate alerts
    for _ in range(num_alerts):
        host = random.choice(assets)
        scenario = random.choice(MITRE_ATTACK_SCENARIOS)
        title, severity, technique, tactic, event_type = scenario
        
        ts = datetime.now(timezone.utc) - timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
        )
        
        src_ip = random.choice(SUSPICIOUS_IPS + [fake.ipv4_public()])
        
        status_weights = [AlertStatus.open, AlertStatus.acknowledged, AlertStatus.investigating,
                          AlertStatus.false_positive, AlertStatus.resolved]
        status = random.choices(status_weights, weights=[40, 20, 15, 10, 15])[0]
        
        alert = Alert(
            title=title,
            description=f"Detected {title} on {host.hostname} from {src_ip}",
            severity=severity,
            status=status,
            source=random.choice(["windows", "linux", "firewall", "network"]),
            source_ip=src_ip,
            destination_ip=fake.ipv4_private() if random.random() > 0.6 else None,
            hostname=host.hostname,
            user=random.choice([fake.user_name(), "administrator", "root"]),
            process_name=random.choice(["powershell.exe", "mimikatz.exe", "psexec.exe", "cmd.exe"]),
            command=random.choice([
                "powershell.exe -enc SGVsbG8=",
                "sekurlsa::logonpasswords",
                "psexec \\\\target cmd /c whoami",
                None
            ]),
            mitre_technique=technique,
            mitre_tactic=tactic,
            risk_score={"critical": random.uniform(80, 100), "high": random.uniform(60, 80),
                        "medium": random.uniform(40, 60), "low": random.uniform(10, 40),
                        "info": random.uniform(0, 10)}[severity.value],
            enrichment_data={"demo": True},
            created_at=ts,
        )
        db.add(alert)
    
    await db.flush()
    print(f"    ✓ {num_logs} logs and {num_alerts} alerts created")


async def seed_incidents(db, num: int = 20):
    print(f"  Seeding {num} incidents...")
    
    incident_templates = [
        ("Ransomware Outbreak - Finance Floor", Severity.critical, IncidentStatus.investigating),
        ("APT Group C2 Communication Detected", Severity.critical, IncidentStatus.containment),
        ("Mass Credential Stuffing Attack", Severity.high, IncidentStatus.resolved),
        ("Insider Threat - Suspicious Data Access", Severity.high, IncidentStatus.investigating),
        ("Supply Chain Compromise Suspected", Severity.critical, IncidentStatus.open),
        ("Phishing Campaign Targeting Executives", Severity.high, IncidentStatus.assigned),
        ("Lateral Movement via PsExec", Severity.high, IncidentStatus.resolved),
        ("Privilege Escalation on DB Server", Severity.critical, IncidentStatus.containment),
        ("DDoS Attack on Web Frontend", Severity.medium, IncidentStatus.resolved),
        ("Suspicious PowerShell Execution Wave", Severity.high, IncidentStatus.investigating),
        ("Data Exfiltration via DNS", Severity.critical, IncidentStatus.recovery),
        ("Unauthorized VPN Access", Severity.medium, IncidentStatus.closed),
        ("Brute Force on SSH", Severity.medium, IncidentStatus.resolved),
        ("Malware on Developer Workstation", Severity.high, IncidentStatus.recovery),
        ("Zero-Day Exploit Attempt", Severity.critical, IncidentStatus.investigating),
    ]
    
    for i in range(num):
        template = incident_templates[i % len(incident_templates)]
        title, severity, status = template
        
        ts = datetime.now(timezone.utc) - timedelta(days=random.randint(0, 30))
        
        incident = Incident(
            title=title,
            description=f"Security incident: {title}. Detected by SentinelX detection engine.",
            severity=severity,
            priority={"critical": 1, "high": 2, "medium": 3, "low": 4}[severity.value],
            status=status,
            tags=random.sample(["ransomware", "apt", "insider", "phishing", "lateral-movement", "exfiltration"], k=2),
            timeline=[
                {
                    "timestamp": ts.isoformat(),
                    "action": "Incident created",
                    "user": "system"
                },
                {
                    "timestamp": (ts + timedelta(minutes=15)).isoformat(),
                    "action": "Alert triggered detection rule",
                    "user": "system"
                }
            ],
            affected_assets=[random.choice(HOSTNAMES), random.choice(HOSTNAMES)],
            mitre_techniques=[random.choice(["T1059.001", "T1110", "T1021.002", "T1003.001"])],
            created_at=ts,
            resolved_at=(ts + timedelta(hours=random.randint(2, 48))) if status in [IncidentStatus.resolved, IncidentStatus.closed] else None
        )
        db.add(incident)
    
    await db.flush()
    print(f"    ✓ {num} incidents created")


async def main():
    print("\n🛡️  SentinelX — Seeding demo data...")
    print("=" * 50)
    
    await init_db()
    
    async with AsyncSessionLocal() as db:
        assets = await seed_assets(db)
        await seed_threat_intel(db)
        await seed_logs_and_alerts(db, assets, num_logs=500, num_alerts=200)
        await seed_incidents(db, num=20)
        await db.commit()
    
    print("=" * 50)
    print("✅  Seeding complete!")
    print("\nDemo credentials:")
    print("  Admin:   admin / SentinelX@2024!")
    print("  Analyst: analyst / Analyst@2024!")
    print("\nRun backend: cd backend && uvicorn main:app --reload")


if __name__ == "__main__":
    asyncio.run(main())
