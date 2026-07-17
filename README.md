# 🛡️ SentinelX — Enterprise SIEM, Threat Detection & SOAR Platform
## 🚀 Production Deployment Guide for Render

This guide walks you through the step-by-step process of deploying the SentinelX platform live on **[Render.com](https://render.com/)** using their free PostgreSQL Database, Python Web Services, and Static Site hosting.

---

## 🏗️ Deployment Architecture on Render
We will deploy three components on Render:
1. **Managed PostgreSQL Database:** Storing our structured logs, detection rules, and incidents.
2. **FastAPI Web Service:** Running the ASGI backend API with Uvicorn.
3. **Static Site:** Hosting the compiled React frontend application.

---

## 🛠️ Step-by-Step Deployment Process

### Step 1: Create a PostgreSQL Database on Render
1. Go to the **[Render Dashboard](https://dashboard.render.com/)**, click **New +** -> **PostgreSQL**.
2. Set the following settings:
   * **Name:** `sentinelx-db`
   * **Database Name:** `sentinelx`
   * **User:** `admin` (or leave blank for auto-generation)
   * **Region:** Choose the region closest to you (e.g., Oregon, Frankfurt, Singapore).
   * **Instance Type:** Select the **Free** tier.
3. Click **Create Database**.
4. Once provisioned, copy the **Internal Database URL** (e.g. `postgresql://admin:password@dpg-xxx-a.oregon-postgres.render.com/sentinelx`).
5. **Format for SQLAlchemy:** Prepend `+asyncpg` to the connection scheme to use the async driver:
   ```text
   postgresql+asyncpg://admin:password@dpg-xxx-a.oregon-postgres.render.com/sentinelx
   ```
   *(Keep this connection string ready; you will need it in Step 3).*

---

### Step 2: Push the Codebase to GitHub
Render deploys apps automatically by linking to a Git repository.
1. Initialize Git in the project root directory and commit your changes:
   ```bash
   git init
   git add .
   git commit -m "Initialize SentinelX SIEM project"
   ```
2. Create a new repository on GitHub (private or public).
3. Link and push your local repository to GitHub:
   ```bash
   git remote add origin https://github.com/your-username/sentinelx.git
   git branch -M main
   git push -u origin main
   ```

---

### Step 3: Deploy the FastAPI Backend Web Service
1. On the Render Dashboard, click **New +** -> **Web Service**.
2. Connect your GitHub repository.
3. Configure the Web Service:
   * **Name:** `sentinelx-backend`
   * **Region:** Select the same region as your database.
   * **Runtime:** `Python`
   * **Build Command:** `pip install -r requirements.txt`
   * **Start Command:** `gunicorn backend.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT`
   * **Instance Type:** Select **Free**.
4. Click **Advanced** and add the following **Environment Variables**:
   * `DATABASE_URL`: The **Internal Database URL** you generated in Step 1 (e.g., `postgresql+asyncpg://...`).
   * `SECRET_KEY`: A secure secret key (generate with: `python -c "import secrets; print(secrets.token_urlsafe(64))"`).
   * `DEBUG`: `false`
   * `CORS_ORIGINS`: `["https://sentinelx-frontend.onrender.com"]` *(replace with your actual Render Static Site URL from Step 4)*.
   * `VIRUSTOTAL_API_KEY`: *(your VirusTotal key)*
   * `GEMINI_API_KEY`: *(your Google Gemini key)*
5. Click **Create Web Service**.
6. Render will build the service and deploy it. Note down the live service URL shown at the top (e.g., `https://sentinelx-backend.onrender.com`).

---

### Step 4: Deploy the React Frontend Static Site
1. On the Render Dashboard, click **New +** -> **Static Site**.
2. Connect your GitHub repository.
3. Configure the Static Site:
   * **Name:** `sentinelx-frontend`
   * **Branch:** `main`
   * **Root Directory:** `frontend`
   * **Build Command:** `npm run build`
   * **Publish Directory:** `dist`
4. Click **Advanced** and add the following **Environment Variables**:
   * `VITE_API_URL`: Your live backend web service URL from Step 3 + `/api/v1` (e.g., `https://sentinelx-backend.onrender.com/api/v1`).
5. Click **Create Static Site**.
6. Render will build the React app and deploy it (e.g., to `https://sentinelx-frontend.onrender.com`).
7. **Important:** Copy this frontend URL and update the `CORS_ORIGINS` variable in your **Backend Web Service** environment settings from Step 3 to ensure your browser requests are authorized.

---

### Step 5: Verify the Live Platform
1. Open your live frontend URL (e.g., `https://sentinelx-frontend.onrender.com`) in your browser.
2. Sign in with the seeded credentials:
   * **Username:** `admin`
   * **Password:** `SentinelX@2024!`
3. Verify that the Dashboard loads and the WebSocket status indicator in the bottom-left sidebar displays green `LIVE`.

---

### Step 6: Roll Out the Endpoint Agent
Compile the agent into a standalone executable that connects directly to the live backend API:
1. In your local terminal, navigate to the agent directory:
   ```bash
   cd endpoint-agent
   ```
2. Create or edit the `.env` file (or set the variables on the host machine):
   ```env
   SENTINELX_API_URL=https://sentinelx-backend.onrender.com/api/v1
   SENTINELX_API_KEY=your_analyst_token_or_api_key
   ```
3. Compile the Python script into a stand-alone Windows executable binary using `PyInstaller`:
   ```bash
   pip install pyinstaller psutil requests pywin32
   pyinstaller --onefile windows/agent.py
   ```
4. Find the compiled executable inside the `dist` directory: `dist/agent.exe`.
5. Deploy `agent.exe` to target machines. Right-click and select **Run as Administrator** to begin streaming telemetry to the live SentinelX instance.
