# CloudSecure FastAPI Backend

## Layout

```
backend-fastapi/
  app/           # FastAPI + SQLAlchemy
  worker/        # Celery tasks + inventory/rule_engine/deep_scan jobs (no Django)
```

## Run locally (with existing docker-compose)

Point `backend` service to this folder or run:

```powershell
cd backend-fastapi
pip install -r requirements.txt
$env:PYTHONPATH = "."
uvicorn app.main:app --reload --port 8000
```

Celery (from project root `.env`):

```powershell
celery -A worker.celery_app:celery_app worker -Q default,inventory -l info
celery -A worker.celery_app:celery_app worker -Q deep_scan -l info
celery -A worker.celery_app:celery_app beat -l info
```

## API compatibility

- `/api/auth/login/`, `/register/`, `/logout/`, `/me/`
- `/api/v1/providers/`, test-connection, inventory-pull, findings, graph, attack-engine, deep-scan
- `Authorization: Token <key>` (unchanged for React frontend)

## Scheduling

Inventory pulls every 30 minutes use **Redis** hash `cloudsecure:inventory:scheduled` (set on test-connection) plus Celery Beat task `worker.tasks.periodic_inventory_pulls`. No django-celery-beat required.

## First-time DB

If starting fresh without Django, run Django migrations once from `backend/` or add Alembic later. Existing deployments keep using `backend` migrations.

## Deep scan (Cartography)

Separate Docker service `celery-deep-scan` uses `Dockerfile.deep-scan` (Cartography **AWS-only**, `--no-deps` — skips OCI/Azure/GCP wheels). API and inventory workers use `requirements-core.txt` only.

```powershell
# AWS-only image — much faster than full Cartography (~5–10 min)
docker compose build --no-cache celery-deep-scan
docker compose up -d celery-deep-scan

# Optional: refresh inventory/API workers after boto3 pin bump
docker compose build backend celery celery-beat
docker compose up -d backend celery celery-beat
```

In the UI: **Deep Scan** → select provider → **Start scan**. Requires a connected AWS provider (same IAM role as inventory) and Neo4j running.

```powershell
docker compose logs -f celery-deep-scan
```
