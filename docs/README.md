# 🛡️ SentinelX — Enterprise SIEM, Threat Detection & SOAR Platform

SentinelX is a production-grade Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) platform. It provides endpoints collection, real-time log ingestion and normalization, rule-based & ML-powered threat detection, multi-tenant and role-based access control, automated playbook execution, threat intelligence enrichment, compliance auditing, and AI-assisted security analysis.

---

## 🚀 Key Features

*   **Log Normalization & Storage**: Unified schema mapping for Windows event logs, Linux syslog, network, and firewall logs.
*   **Real-time Detection Engine**: Core signature, threshold, and Indicators of Compromise (IOC) matching against ingested logs.
*   **Machine Learning Anomalies**: Advanced anomaly detection with Isolation Forest, One-Class SVM, DBSCAN clustering, and GeoIP-based Impossible Travel detection.
*   **SOAR Automations**: Automated playbooks mapping threat scenarios to containment actions (e.g., blocking IPs, disabling user accounts, killing processes).
*   **Threat Intel Enrichment**: Automated correlation of events against VirusTotal, AbuseIPDB, AlienVault OTX, and Shodan.
*   **AI Analyst**: AI-powered summaries, MITRE ATT&CK technique explanations, and customized remediation workflows powered by Google Gemini and OpenAI.
*   **Compliance Frameworks**: Continuous posture evaluation scoring against PCI DSS, SOC2, ISO27001, HIPAA, and GDPR.
*   **Multi-channel Notifications**: Instant critical routing alerts to Email, Slack, Telegram, Discord, and Microsoft Teams.
*   **Reporting**: Instantly generate executive summaries, compliance findings, asset inventories, or incident timelines in PDF, Excel, CSV, or JSON formats.

---

## 📦 Project Structure

```text
├── backend/
│   ├── api/                 # FastAPI routes (auth, alerts, assets, compliance, etc.)
│   ├── auth/                # JWT Token & API Key Authentication logic
│   ├── cloud/               # Cloud Security (AWS, Azure, GCP log collectors)
│   ├── compliance/          # PCI DSS, SOC2, ISO27001, HIPAA, GDPR engines
│   ├── detection/           # Signature, threshold detection & MITRE mappers
│   ├── enrichment/          # VirusTotal, AbuseIPDB, OTX, Shodan enrichment API
│   ├── ml/                  # Isolation Forest, DBSCAN, SVM anomaly detection
│   ├── models/              # SQLAlchemy database models
│   ├── normalization/       # Log normalization schema & Windows Event ID mapping
│   ├── soar/                # SOAR playbooks and automation actions
│   ├── main.py              # Application entry point & Middlewares
│   └── database.py          # SQLite database connections
├── endpoint-agent/
│   ├── linux/               # Python-based Linux collector agent
│   └── windows/             # Python-based Windows Event Log collector agent
├── frontend/                # React (Vite, TypeScript, Recharts) dashboard UI
└── tests/                   # Pytest automated test suite (conftest, auth, ML, engine)
```

---

## 🛠️ Quick Start

### 1. Backend Setup
1. Clone the repository and navigate to the project directory.
2. Initialize virtual environment and install packages:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Set up configurations in `.env` (copy variables from `.env` template).
4. Run the seed data script:
   ```bash
   python scripts/seed_data.py
   ```
5. Start the backend development server:
   ```bash
   uvicorn backend.main:app --reload
   ```

### 2. Frontend Setup
1. Navigate to the `frontend/` directory:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

### 3. Run Automated Tests
```bash
pytest -v
```
