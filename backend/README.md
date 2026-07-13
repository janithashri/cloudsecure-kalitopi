# Legacy Django backend (migrations only)

CloudSecure **runs on `backend-fastapi/`** (Docker, Celery, API). This folder is kept for:

- **Database migrations** — `python manage.py migrate` on fresh Postgres (see `backend-fastapi/README.md`)
- **Historical reference** — Django models mirror `backend-fastapi/app/models/orm.py`

Do **not** use this for the API or workers in production. Safe to remove from disk if you already migrated the DB and use `backend-fastapi/scripts/init_anomaly_tables.py` for new tables.

## One-time migrate (fresh DB)

```powershell
cd backend
pip install -r requirements.txt
python manage.py migrate
```

Then run the stack from project root with `backend-fastapi` via Docker Compose.
