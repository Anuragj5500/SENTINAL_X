"""
AI Security Analyst — uses Gemini/OpenAI to analyze alerts and provide
incident summaries, risk assessments, MITRE explanations, and remediation steps.
Falls back to rule-based analysis in demo mode.
"""
from backend.config import settings
from backend.detection.mitre_mapper import get_technique_details

DEMO_MODE = not (settings.GEMINI_API_KEY or settings.OPENAI_API_KEY)


SEVERITY_RISK_MAP = {
    "critical": "CRITICAL — Immediate action required. Potential active compromise.",
    "high": "HIGH — Significant threat detected. Investigate immediately.",
    "medium": "MEDIUM — Suspicious activity. Review and assess impact.",
    "low": "LOW — Informational event. Monitor for patterns.",
    "info": "INFO — Normal activity recorded for audit purposes.",
}

TECHNIQUE_REMEDIATION = {
    "T1059.001": [
        "Investigate the PowerShell command and its origin",
        "Disable PowerShell for non-admin users via AppLocker or WDAC",
        "Enable PowerShell ScriptBlock logging (Event ID 4104)",
        "Check for persistence mechanisms in startup locations",
        "Collect memory dump if compromise is suspected"
    ],
    "T1110": [
        "Block the source IP at the firewall",
        "Enable account lockout policy (5 attempts / 15 min lockout)",
        "Reset password for targeted accounts immediately",
        "Enable MFA for all accounts",
        "Review other login attempts from this IP"
    ],
    "T1003.001": [
        "ISOLATE the endpoint immediately",
        "Collect memory dump for forensic analysis",
        "Reset all domain credentials (especially privileged accounts)",
        "Check for additional lateral movement from this host",
        "Review LSASS access patterns using Sysmon Event ID 10"
    ],
    "T1021.002": [
        "Block SMB traffic from unexpected sources",
        "Review admin share access (ADMIN$, C$) logs",
        "Disable unnecessary SMB shares",
        "Reset credentials for any accounts used in the lateral movement",
        "Check all destination hosts for malware"
    ],
    "T1486": [
        "ISOLATE the affected system immediately — disconnect from network",
        "Do NOT pay ransom — contact incident response team",
        "Identify ransomware variant using ID Ransomware tool",
        "Restore from clean backups after securing the environment",
        "Scan all connected systems for infection"
    ],
    "T1053.005": [
        "Review all new scheduled tasks: schtasks /query",
        "Delete suspicious tasks immediately",
        "Check the task's executable for malware using VirusTotal",
        "Review auto-start locations (HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)",
        "Enable audit policy for scheduled task events"
    ],
    "DEFAULT": [
        "Acknowledge and investigate the alert",
        "Review related logs in the 30-minute window",
        "Check if the affected asset is part of an active incident",
        "Escalate to senior analyst if unsure",
        "Document findings in the incident timeline"
    ]
}


async def analyze_alert(alert_data: dict) -> str:
    """Generate AI analysis for an alert."""
    if DEMO_MODE:
        return _demo_analysis(alert_data)
    
    try:
        if settings.GEMINI_API_KEY:
            return await _gemini_analysis(alert_data)
        elif settings.OPENAI_API_KEY:
            return await _openai_analysis(alert_data)
    except Exception as e:
        return _demo_analysis(alert_data) + f"\n\n[Note: AI API error — {str(e)[:100]}]"
    
    return _demo_analysis(alert_data)


def _demo_analysis(alert_data: dict) -> str:
    technique_id = alert_data.get("mitre_technique", "")
    tactic = alert_data.get("mitre_tactic", "Unknown")
    severity = alert_data.get("severity", "medium")
    title = alert_data.get("title", "Unknown Alert")
    hostname = alert_data.get("hostname", "Unknown Host")
    source_ip = alert_data.get("source_ip", "Unknown IP")
    
    technique_details = get_technique_details(technique_id) if technique_id else {}
    technique_name = technique_details.get("technique", technique_id or "Unknown")
    
    remediations = TECHNIQUE_REMEDIATION.get(technique_id, TECHNIQUE_REMEDIATION["DEFAULT"])
    remediation_text = "\n".join(f"  {i+1}. {r}" for i, r in enumerate(remediations))
    
    risk_text = SEVERITY_RISK_MAP.get(severity, SEVERITY_RISK_MAP["medium"])
    
    return f"""## AI Security Analysis

**Alert:** {title}
**Affected Host:** {hostname}
**Source IP:** {source_ip}

### Risk Assessment
{risk_text}

### MITRE ATT&CK Classification
- **Tactic:** {tactic}
- **Technique:** {technique_name} ({technique_id or "N/A"})
- **Kill Chain Stage:** {tactic}

### Incident Summary
This alert indicates {'a potential active attack' if severity in ['critical', 'high'] else 'suspicious activity'} on **{hostname}**. 
The detected behavior aligns with the **{tactic}** phase of the MITRE ATT&CK framework, 
specifically technique **{technique_name}**. 
{'Immediate investigation is required.' if severity == 'critical' else 'This should be investigated within the hour.' if severity == 'high' else 'Review during your next analyst rotation.'}

### Probable Root Cause
Based on the alert pattern, this may be caused by:
- External threat actor or insider threat attempting **{tactic.lower()}**
- Automated attack tool or script targeting known vulnerabilities
- Potential malware execution or lateral movement activity

### Recommended Actions
{remediation_text}

### Threat Hunting Pivot Points
- Search for similar events from IP: `{source_ip}`
- Review process tree on host: `{hostname}`
- Check for related alerts in the past 24 hours
- Look for C2 beacon patterns in network logs

---
*Analysis generated by SentinelX AI Analyst (Demo Mode)*
"""


async def _gemini_analysis(alert_data: dict) -> str:
    import httpx
    
    prompt = f"""You are an expert SOC Analyst. Analyze this security alert and provide:
1. Incident Summary (2-3 sentences)
2. Risk Assessment (Critical/High/Medium/Low with explanation)
3. MITRE ATT&CK explanation (tactic, technique, what it means)
4. Probable Root Cause
5. Recommended Remediation Steps (numbered list)
6. Threat Hunting queries to investigate further

Alert Details:
{alert_data}

Be concise and technical. Format in markdown."""

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={settings.GEMINI_API_KEY}",
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=30
        )
        data = response.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]


async def _openai_analysis(alert_data: dict) -> str:
    import httpx
    
    prompt = f"""You are an expert SOC Analyst. Analyze this security alert:
{alert_data}

Provide: incident summary, risk assessment, MITRE explanation, root cause, and remediation steps in markdown."""
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 800
            },
            timeout=30
        )
        data = response.json()
        return data["choices"][0]["message"]["content"]
