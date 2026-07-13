import logging
import os

from celery import Celery

# Deep-scan imports cartography (only installed in celery-deep-scan image).
_CELERY_IMPORTS = ["worker.tasks", "worker.jobs.anomaly_detection.task"]
if os.environ.get("CELERY_IMPORT_DEEP_SCAN", "").lower() in ("1", "true", "yes"):
    _CELERY_IMPORTS.append("worker.jobs.deep_scan.scan")
    _CELERY_IMPORTS.append("worker.jobs.deep_scan.graph_analytics_task")
from celery.signals import worker_ready

from app.core.config import get_settings

settings = get_settings()

os.environ.setdefault("AWS_DEFAULT_REGION", settings.aws_default_region)

celery_app = Celery("cloudsecure")
celery_app.conf.update(
    broker_url=settings.valkey_url,
    result_backend=settings.valkey_url,
    broker_connection_retry_on_startup=True,
    accept_content=["json"],
    task_serializer="json",
    result_serializer="json",
    task_routes={
        "worker.tasks.perform_inventory_pull_task": {"queue": "inventory"},
        "worker.jobs.deep_scan.scan.run": {"queue": "deep_scan"},
        "worker.jobs.deep_scan.graph_analytics.run": {"queue": "deep_scan"},
        "worker.jobs.anomaly_detection.task.run_anomaly_detection": {"queue": "anomaly"},
        "worker.tasks.periodic_inventory_pulls": {"queue": "inventory"},
    },
    beat_schedule={
        "periodic-inventory-pulls": {
            "task": "worker.tasks.periodic_inventory_pulls",
            "schedule": 30.0 * 60.0,
        },
    },
    imports=_CELERY_IMPORTS,
)

celery_app.autodiscover_tasks(["worker"])


@worker_ready.connect
def load_opa_policies(sender=None, **kwargs):
    logger = logging.getLogger(__name__)
    try:
        from worker.jobs.rule_engine.opa_client import load_all_rules

        load_all_rules()
        logger.info("OPA policies loaded")
    except Exception as e:
        logger.warning("OPA policy load failed (non-fatal): %s", e)
