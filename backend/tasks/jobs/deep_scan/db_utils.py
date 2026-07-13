from datetime import datetime, timezone
from typing import Any

from cartography.config import Config as IngestionConfig

from api.models import DeepScan as DeepScanModel
from api.models import DeepScanStateChoices as StateChoices
from providers.models import Provider as ProviderModel


def can_provider_run_deep_scan(tenant_id: str, provider_id: int) -> bool:
    try:
        ProviderModel.objects.get(id=provider_id, tenant_id=tenant_id)
    except ProviderModel.DoesNotExist:
        return False
    return True


def retrieve_deep_scan(tenant_id: str, scan_id: str) -> DeepScanModel | None:
    try:
        return DeepScanModel.objects.get(scan_id=scan_id, tenant_id=tenant_id)
    except DeepScanModel.DoesNotExist:
        return None


def mark_scan_executing(
    deep_scan: DeepScanModel, task_id: str, ingestion_config: IngestionConfig
) -> None:
    deep_scan.task_id = task_id
    deep_scan.state = StateChoices.EXECUTING
    deep_scan.started_at = datetime.now(tz=timezone.utc)
    deep_scan.update_tag = ingestion_config.update_tag
    deep_scan.graph_database = ingestion_config.neo4j_database
    deep_scan.save(
        update_fields=["task_id", "state", "started_at", "update_tag", "graph_database"]
    )


def mark_scan_finished(
    deep_scan: DeepScanModel, state, ingestion_exceptions: dict[str, Any]
) -> None:
    now = datetime.now(tz=timezone.utc)
    duration = int((now - deep_scan.started_at).total_seconds()) if deep_scan.started_at else 0
    deep_scan.state = state
    deep_scan.progress = 100
    deep_scan.completed_at = now
    deep_scan.duration = duration
    deep_scan.ingestion_exceptions = ingestion_exceptions
    deep_scan.save(
        update_fields=["state", "progress", "completed_at", "duration", "ingestion_exceptions"]
    )


def update_scan_progress(deep_scan: DeepScanModel, progress: int) -> None:
    deep_scan.progress = progress
    deep_scan.save(update_fields=["progress"])


def get_superseded_scans(
    tenant_id: str, provider_id: str, current_scan_id: str
) -> list[DeepScanModel]:
    qs = (
        DeepScanModel.objects.filter(
            tenant_id=tenant_id,
            provider_id=provider_id,
            state=StateChoices.COMPLETED,
            is_graph_database_deleted=False,
        )
        .exclude(id=current_scan_id)
        .all()
    )
    return list(qs)


def mark_old_scan_graph_deleted(old_scan: DeepScanModel) -> None:
    old_scan.is_graph_database_deleted = True
    old_scan.save(update_fields=["is_graph_database_deleted"])


def fail_scan_if_stuck(tenant_id: str, scan_id: str, error: str) -> None:
    scan = retrieve_deep_scan(tenant_id, scan_id)
    if scan and scan.state not in (StateChoices.COMPLETED, StateChoices.FAILED):
        mark_scan_finished(scan, StateChoices.FAILED, {"global_error": error})
