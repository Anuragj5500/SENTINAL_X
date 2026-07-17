# SentinelX — Deployment Guide

This guide outlines options for deploying SentinelX in testing, simulation labs, or production-grade environments.

---

## 🛠️ Deployment Modes

### 1. Development / Demonstration Mode (Default)
In development mode, SQLite and local python environments are used. External APIs (Gemini, VirusTotal, AbuseIPDB) fall back to mock datasets if credentials are omitted from `.env`.

### 2. Production / Self-Hosted Mode
For production scaling:
*   **Database**: Migrated to a dedicated PostgreSQL instance using the `postgresql+asyncpg` URL in config.
*   **Log Storage**: An optional Elasticsearch cluster is deployed to store high-volume logs, while PostgreSQL stores users, assets, alerts, incidents, and playbooks.
*   **Web Server**: Uvicorn runs behind a reverse proxy (Nginx or Traefik) providing SSL/TLS termination.
*   **Rate Limiting & Hardening**: Rate limits are enforced on critical paths (`/api/v1/auth/*`), and security headers block framing and clickjacking.

---

## 🐋 Docker Compose Deployment (Recommended)

Create a `docker-compose.yml` file in the project root:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: sentinelx_db
    environment:
      POSTGRES_USER: sentinelx
      POSTGRES_PASSWORD: DBpassword123!
      POSTGRES_DB: sentinelx
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sentinelx"]
      interval: 10s
      timeout: 5s
      retries: 5

  backend:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: sentinelx_backend
    environment:
      - DATABASE_URL=postgresql+asyncpg://sentinelx:DBpassword123!@postgres:5432/sentinelx
      - SECRET_KEY=YOUR_SECURE_GENERATED_KEY_HERE
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - SMTP_HOST=${SMTP_HOST}
      - SMTP_USER=${SMTP_USER}
      - SMTP_PASS=${SMTP_PASS}
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy

  frontend:
    image: nginx:alpine
    container_name: sentinelx_frontend
    volumes:
      - ./frontend/dist:/usr/share/nginx/html
      - ./nginx.conf:/etc/nginx/nginx.conf
    ports:
      - "80:80"
    depends_on:
      - backend

volumes:
  postgres_data:
```

---

## 🔒 Hardening checklist

1.  **JWT Secret Rotation**: Generate a cryptographically secure key:
    ```bash
    python -c "import secrets; print(secrets.token_urlsafe(64))"
    ```
2.  **Enable MFA**: Ensure all administrator accounts configure TOTP MFA upon initialization.
3.  **Rotate API Keys**: Periodically revoke and regenerate keys for Windows and Linux endpoint agents in the Admin panel.
4.  **Enforce TLS 1.3**: Configure Nginx reverse proxy to reject traffic from deprecated security protocols (TLS 1.0, 1.1).
