from celery import shared_task
from django.utils.timezone import now

from api.models import InventoryRun
from tasks.jobs.inventory import run_inventory_pull


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    queue="inventory",
    acks_late=True,
    reject_on_worker_lost=True,
)
def perform_inventory_pull_task(self, tenant_id: int, provider_id: int):
    run = InventoryRun.objects.create(
        tenant_id=tenant_id,
        provider_id=provider_id,
        state="running",
        started_at=now(),
    )
    try:
        stats = run_inventory_pull(tenant_id, provider_id, run)
        final_state = "partial" if stats.get("fetch_failed", 0) > 0 else "completed"
        run.state = final_state
        run.stats = stats
    except Exception as exc:
        run.state = "failed"
        run.stats = {"error": str(exc)}
        raise self.retry(exc=exc)
    finally:
        run.completed_at = now()
        run.save()
