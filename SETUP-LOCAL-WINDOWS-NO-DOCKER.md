# CloudSecure — Local setup on Windows (no Docker)

Backend + frontend on the host. You still need **4 services**: PostgreSQL, Redis, Neo4j, OPA.

---

## 1. `.env` (project root)

Edit `C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\.env`:

```env
SECRET_KEY=<python -c "import secrets; print(secrets.token_urlsafe(50))">
DEBUG=True
POSTGRES_DB=cloudsecure
POSTGRES_USER=cloudsecure
POSTGRES_PASSWORD=localpostgres123
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
VALKEY_URL=redis://127.0.0.1:6379/0
NEO4J_URI=neo4j+s://YOUR_INSTANCE.databases.neo4j.io
NEO4J_USER=neo4j
NEO4J_PASSWORD=
NEO4J_SHARED_DATABASE=neo4j
OPA_URL=http://127.0.0.1:8181
AWS_DEFAULT_REGION=us-east-1
```

---

## 2. PostgreSQL

**Install:** https://www.postgresql.org/download/windows/ (or `winget install PostgreSQL.PostgreSQL.16`)

**Create DB** (psql or pgAdmin):

```sql
CREATE USER cloudsecure WITH PASSWORD 'localpostgres123';
CREATE DATABASE cloudsecure OWNER cloudsecure;
```

**Migrations** (one-time, uses Django from `backend/`):

```powershell
cd C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:POSTGRES_HOST="localhost"
$env:POSTGRES_PASSWORD="localpostgres123"
$env:SECRET_KEY="dev-secret-key"
python manage.py migrate
python manage.py createsuperuser
```

---

## 3. Redis (Celery broker) — **fixes your Celery error**

Celery needs something listening on **port 6379**.

**Option A — Memurai (Redis-compatible, Windows):**

- Download: https://www.memurai.com/get-memurai
- Install → service starts on `127.0.0.1:6379`

**Option B — Redis via winget:**

```powershell
winget install Redis.Redis
```

Then start Redis (path varies; often as a Windows service).

**Verify:**

```powershell
Test-NetConnection 127.0.0.1 -Port 6379
```

Should show `TcpTestSucceeded : True`.

---

## 4. Neo4j

**Install:** https://neo4j.com/download/ → Neo4j Desktop or Community Server.

- Set password to match `NEO4J_PASSWORD` in `.env` (e.g. `localneo4j123`)
- Bolt URL: `bolt://localhost:7687`
- Start the database

**Verify:** open http://localhost:7474

---

## 5. OPA (compliance rules)

**Download** `opa_windows_amd64.exe` from https://github.com/open-policy-agent/opa/releases/latest

Rename and run:

```powershell
mkdir C:\Tools\opa -Force
# move opa.exe to C:\Tools\opa\opa.exe
C:\Tools\opa\opa.exe run --server --addr 127.0.0.1:8181
```

Leave this terminal open.

---

## 6. Run the app (4 terminals)

### Terminal 1 — API (already working)

```powershell
cd C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\backend-fastapi
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\backend-fastapi"
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Terminal 2 — Celery worker (**use `--pool=solo` on Windows**)

```powershell
cd C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\backend-fastapi
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\backend-fastapi"
python -m celery -A worker.celery_app:celery_app worker --loglevel=info -Q default,inventory --pool=solo
```

### Terminal 3 — Celery beat (optional)

```powershell
cd C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\backend-fastapi
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\backend-fastapi"
python -m celery -A worker.celery_app:celery_app beat --loglevel=info
```

### Terminal 4 — Frontend

```powershell
cd C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\frontend
$env:VITE_API_URL = "http://localhost:8000"
npm run dev -- --host
```

---

## What was wrong in your Celery log

`Error 10061 ... 127.0.0.1:6379` = **nothing is running on port 6379**. Start Redis/Memurai first, then restart Celery with `--pool=solo`.

When connected you should see:

```text
Connected to redis://127.0.0.1:6379/0
celery@... ready.
```

---

## Minimum to test login + API (no scans)

| Service    | Required? |
|-----------|-----------|
| PostgreSQL | Yes       |
| Redis      | Only for scans / Celery |
| Neo4j      | For graph dashboard |
| OPA        | For compliance findings |

Login and providers work with **PostgreSQL only**. Scans need **Redis + Celery + Neo4j + OPA**.
