import json

import redis

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.db import repositories as repo
from worker.celery_app import celery_app
from worker.jobs.inventory import run_inventory_pull

SCHEDULE_KEY = "cloudsecure:inventory:scheduled"


def _redis_client():
    return redis.from_url(get_settings().valkey_url)


def schedule_inventory_pull(provider_id: int, tenant_id: int) -> None:
    r = _redis_client()
    r.hset(SCHEDULE_KEY, str(provider_id), json.dumps({"tenant_id": tenant_id}))


def disable_inventory_pull(provider_id: int) -> None:
    r = _redis_client()
    r.hdel(SCHEDULE_KEY, str(provider_id))


@celery_app.task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    queue="inventory",
    acks_late=True,
    reject_on_worker_lost=True,
    name="worker.tasks.perform_inventory_pull_task",
)
def perform_inventory_pull_task(self, tenant_id: int, provider_id: int):
    run = None
    with SessionLocal() as db:
        run = repo.create_inventory_run(db, tenant_id, provider_id)
    try:
        stats = run_inventory_pull(tenant_id, provider_id, run)
        final_state = "partial" if stats.get("fetch_failed", 0) > 0 else "completed"
        with SessionLocal() as db:
            repo.finalize_inventory_run(db, run.id, final_state, stats)
    except Exception as exc:
        with SessionLocal() as db:
            repo.finalize_inventory_run(db, run.id, "failed", {"error": str(exc)})
        raise self.retry(exc=exc)


@celery_app.task(name="worker.tasks.periodic_inventory_pulls", queue="inventory")
def periodic_inventory_pulls():
    r = _redis_client()
    entries = r.hgetall(SCHEDULE_KEY)
    for provider_id_bytes, payload_bytes in entries.items():
        provider_id = int(provider_id_bytes.decode())
        payload = json.loads(payload_bytes.decode())
        tenant_id = int(payload["tenant_id"])
        with SessionLocal() as db:
            if repo.has_running_inventory_run(db, provider_id):
                continue
        perform_inventory_pull_task.delay(tenant_id, provider_id)
