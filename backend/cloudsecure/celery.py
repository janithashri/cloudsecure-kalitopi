import logging
import os

from celery import Celery
from celery.signals import worker_ready

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cloudsecure.settings")

logger = logging.getLogger(__name__)

app = Celery("cloudsecure")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks(["tasks"])
app.autodiscover_tasks(["tasks.jobs.deep_scan"], related_name="scan")


@worker_ready.connect
def load_opa_policies(sender=None, **kwargs):
    """
    Load all Rego policies into the running OPA server.
    Non-fatal: inventory/rule engine can still proceed, but findings may be empty.
    """
    try:
        from django.conf import settings

        from tasks.jobs.rule_engine.opa_client import load_all_rules

        rules_dir = getattr(
            settings,
            "RULES_DIR",
            os.path.join(settings.BASE_DIR, "tasks", "jobs", "inventory", "rules"),
        )
        load_all_rules(rules_dir)
        logger.info("OPA policies loaded from %s", rules_dir)
    except Exception as e:
        logger.warning("OPA policy load failed (non-fatal): %s", e)
