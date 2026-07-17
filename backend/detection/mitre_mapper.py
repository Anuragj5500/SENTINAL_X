"""
MITRE ATT&CK Framework mapper — provides technique details and tactic groupings.
"""

MITRE_DATA = {
    # Initial Access
    "T1566": {"technique": "Phishing", "tactic": "Initial Access", "sub": None},
    "T1566.001": {"technique": "Spearphishing Attachment", "tactic": "Initial Access", "sub": "T1566.001"},
    "T1190": {"technique": "Exploit Public-Facing Application", "tactic": "Initial Access", "sub": None},
    "T1133": {"technique": "External Remote Services", "tactic": "Initial Access", "sub": None},
    
    # Execution
    "T1059": {"technique": "Command and Scripting Interpreter", "tactic": "Execution", "sub": None},
    "T1059.001": {"technique": "PowerShell", "tactic": "Execution", "sub": "T1059.001"},
    "T1059.003": {"technique": "Windows Command Shell", "tactic": "Execution", "sub": "T1059.003"},
    "T1059.004": {"technique": "Unix Shell", "tactic": "Execution", "sub": "T1059.004"},
    "T1203": {"technique": "Exploitation for Client Execution", "tactic": "Execution", "sub": None},
    
    # Persistence
    "T1053": {"technique": "Scheduled Task/Job", "tactic": "Persistence", "sub": None},
    "T1053.005": {"technique": "Scheduled Task", "tactic": "Persistence", "sub": "T1053.005"},
    "T1053.003": {"technique": "Cron", "tactic": "Persistence", "sub": "T1053.003"},
    "T1543": {"technique": "Create or Modify System Process", "tactic": "Persistence", "sub": None},
    "T1543.003": {"technique": "Windows Service", "tactic": "Persistence", "sub": "T1543.003"},
    "T1136": {"technique": "Create Account", "tactic": "Persistence", "sub": None},
    "T1136.001": {"technique": "Local Account", "tactic": "Persistence", "sub": "T1136.001"},
    
    # Privilege Escalation
    "T1134": {"technique": "Access Token Manipulation", "tactic": "Privilege Escalation", "sub": None},
    "T1548": {"technique": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation", "sub": None},
    
    # Defense Evasion
    "T1027": {"technique": "Obfuscated Files or Information", "tactic": "Defense Evasion", "sub": None},
    "T1036": {"technique": "Masquerading", "tactic": "Defense Evasion", "sub": None},
    "T1562": {"technique": "Impair Defenses", "tactic": "Defense Evasion", "sub": None},
    
    # Credential Access
    "T1110": {"technique": "Brute Force", "tactic": "Credential Access", "sub": None},
    "T1003": {"technique": "OS Credential Dumping", "tactic": "Credential Access", "sub": None},
    "T1003.001": {"technique": "LSASS Memory", "tactic": "Credential Access", "sub": "T1003.001"},
    
    # Discovery
    "T1046": {"technique": "Network Service Scanning", "tactic": "Discovery", "sub": None},
    "T1083": {"technique": "File and Directory Discovery", "tactic": "Discovery", "sub": None},
    "T1087": {"technique": "Account Discovery", "tactic": "Discovery", "sub": None},
    
    # Lateral Movement
    "T1021": {"technique": "Remote Services", "tactic": "Lateral Movement", "sub": None},
    "T1021.002": {"technique": "SMB/Windows Admin Shares", "tactic": "Lateral Movement", "sub": "T1021.002"},
    "T1570": {"technique": "Lateral Tool Transfer", "tactic": "Lateral Movement", "sub": None},
    
    # Collection
    "T1056": {"technique": "Input Capture", "tactic": "Collection", "sub": None},
    "T1074": {"technique": "Data Staged", "tactic": "Collection", "sub": None},
    
    # Exfiltration
    "T1041": {"technique": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "sub": None},
    "T1048": {"technique": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "sub": None},
    "T1048.003": {"technique": "Exfiltration Over DNS", "tactic": "Exfiltration", "sub": "T1048.003"},
    
    # Command and Control
    "T1071": {"technique": "Application Layer Protocol", "tactic": "Command and Control", "sub": None},
    "T1095": {"technique": "Non-Application Layer Protocol", "tactic": "Command and Control", "sub": None},
    
    # Impact
    "T1486": {"technique": "Data Encrypted for Impact", "tactic": "Impact", "sub": None},
    "T1489": {"technique": "Service Stop", "tactic": "Impact", "sub": None},
    "T1490": {"technique": "Inhibit System Recovery", "tactic": "Impact", "sub": None},
}

TACTICS_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Command and Control", "Impact"
]


def get_technique_details(technique_id: str) -> dict:
    return MITRE_DATA.get(technique_id, {
        "technique": technique_id,
        "tactic": "Unknown",
        "sub": None
    })


def get_tactics_list() -> list:
    return TACTICS_ORDER


def get_all_techniques() -> list:
    return [
        {"id": k, **v}
        for k, v in MITRE_DATA.items()
    ]
