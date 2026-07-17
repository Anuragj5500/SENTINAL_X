# SentinelX Build Tasks

## Phase 1 — Backend Completion
- [x] `backend/main.py` — FastAPI entry point
- [x] `backend/detection/rules/default_rules.json` — 20 detection rules (expanded)
- [x] `backend/api/threat_intel.py` — Threat intel API
- [x] `backend/api/threat_hunting.py` — Threat hunting API
- [x] `backend/api/soar.py` — SOAR/Playbooks API
- [x] `backend/api/rules.py` — Detection rules CRUD API
- [x] `backend/api/vulnerabilities.py` — Vulnerability management API
- [x] `backend/api/reports.py` — Report generation API
- [x] `backend/api/admin.py` — Admin panel API
- [x] `backend/api/websocket.py` — WebSocket real-time alerts (integrated directly in `main.py`)
- [x] `scripts/seed.py` — Database seed script (`seed_data.py`)
- [x] `.env.example` — Environment template

## Phase 2 — Frontend (React + Vite)
- [x] Initialize Vite React project
- [x] `frontend/src/index.css` — Design system
- [x] `frontend/src/App.jsx` — Router + layout
- [x] `frontend/src/api/client.js` — Axios API client
- [x] `frontend/src/store/` — Zustand auth store (`authStore.js`)
- [x] Login page
- [x] Dashboard page (charts, heatmap)
- [x] Alerts page + detail
- [x] Incidents page + detail
- [x] Threat hunting page
- [x] Assets page
- [x] Rules page
- [x] SOAR page
- [x] Reports page
- [x] Admin page

## Phase 3 — Endpoint Agents
- [x] `endpoint-agent/windows/agent.py`
- [x] `endpoint-agent/linux/agent.py`
- [x] `endpoint-agent/requirements.txt`

## Phase 4 — Infrastructure
- [ ] `docker-compose.yml`
- [ ] `backend/Dockerfile`
- [ ] `frontend/Dockerfile`
