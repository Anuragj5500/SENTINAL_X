# SentinelX — System Architecture Document

SentinelX follows a modular, pipeline-oriented architecture designed to handle secure event collection, rapid normalisation, automated detection, threat enrichment, and incident mitigation.

---

## 🏗️ Architectural Overview

```text
  +--------------------------------------------------------------+
  |                      Endpoints & Collectors                  |
  |  [Win Event Logs]   [Linux Auth Logs]   [Cloud Logs (AWS/GCP)]|
  +------------------------------+-------------------------------+
                                 | (API Key / JWT HTTP POST)
                                 v
  +--------------------------------------------------------------+
  |                    Log Normalisation Engine                  |
  |  - Windows Event ID mapper to schemas                        |
  |  - Dynamic field parser & static tagging                      |
  +------------------------------+-------------------------------+
                                 | (Unified JSON Schema)
                                 v
  +--------------------------------------------------------------+
  |                     Real-Time Detection                      |
  |  - Signature checking againstDefault Rules                   |
  |  - Threshold & Brute force counting                          |
  |  - ML Anomaly Engine (SVM, Isolation Forest, DBSCAN)          |
  +----------------------+---------------+-----------------------+
                         |               |
                         | (Alert Alert) | (Incident Created)
                         v               v
  +----------------------v-------+-------v-----------------------+
  |              SOAR            |         Threat Intelligence   |
  |  - Automated Playbooks       |  - VirusTotal / AbuseIPDB     |
  |  - Host Isolation            |  - AlienVault OTX / Shodan    |
  |  - IP / Process Blocking     |  - AI Analysis (Gemini/GPT-4) |
  +----------------------+-------+---------------+---------------+
                         |                       |
                         +-----------+-----------+
                                     |
                                     v
  +--------------------------------------------------------------+
  |                       SentinelX APIs                         |
  |  - JWT / RBAC Authentication (JWT Bearer Token)               |
  |  - Compliance Posture Engine (PCI DSS, SOC2, HIPAA, GDPR)    |
  |  - Reporting Engine (PDF, Excel, CSV)                        |
  |  - Event Hunt & Threat Hunting Query System                  |
  +--------------------------------------------------------------+
```

---

## 📁 Key Components

### 1. Log Normalisation Engine
Converts unstructured and platform-specific log schemas (Windows Event Log channel outputs, syslog entries, cloud trails) into a unified database format:
*   **Normalized Fields**: `timestamp`, `hostname`, `user`, `event_type`, `source_ip`, `destination_ip`, `severity`, `event_id`, `command`, `process_name`, `file_path`, `hash_value`, `status`, `source_platform`, `tags`.

### 2. Detection Engine
Matches events sequentially against in-memory signatures and threshold definitions.
*   **Signature Matching**: Matches keywords in command strings, process names, or file paths.
*   **Threshold Detection**: Identifies repeated occurrences (e.g., 5+ failed login attempts within 60 seconds).
*   **IOC Matching**: Correlates IP addresses, domains, and file hashes against threat intelligence feeds.

### 3. Machine Learning & Anomaly Detection
Uses Python security modules to evaluate outliers:
*   **Isolation Forest**: Unsupervised anomaly detection based on time of day, cmd length, and process features.
*   **One-Class SVM**: Outlier classification for command execution anomalies.
*   **DBSCAN**: Cluster analysis of user login patterns to identify unusual authentication times.
*   **Impossible Travel**: Haversine distance calculations checking velocity vectors of consecutive user login events.

### 4. SOAR (Security Orchestration, Automation, & Response)
Automates incident mitigation:
*   **Playbooks**: Configurable maps connecting alert types to sequences of response tasks.
*   **Actions**: Simulated and actual triggers to isolate compromised endpoints, terminate malicious PIDs, or update firewall rules.

### 5. Compliance & Reporting
*   **Compliance Evaluation**: Evaluates overall posture by querying active alerts, vulnerability scores, audit trail completeness, and asset configuration parameters against major frameworks.
*   **Unified Reporting**: Assembles summary data, incident timelines, and asset groups, compiling them into downloadable **PDF**, **Excel**, **CSV**, or raw **JSON** documents.
