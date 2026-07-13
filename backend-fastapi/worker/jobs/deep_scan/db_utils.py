from datetime import datetime, timezone
from typing import Any

from cartography.config import Config as IngestionConfig
from sqlalchemy import select

from app.core.database import SessionLocal
from app.db import repositories as repo
from app.models.orm import DeepScan

EXECUTING = "EXECUTING"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
SCHEDULED = "SCHEDULED"


def can_provider_run_deep_scan(tenant_id: str, provider_id: int) -> bool:
    with SessionLocal() as db:
        return repo.get_provider_for_tenant(db, provider_id, int(tenant_id)) is not None


def retrieve_deep_scan(tenant_id: str, scan_id: str) -> DeepScan | None:
    with SessionLocal() as db:
        return repo.retrieve_deep_scan(db, tenant_id, scan_id)


def mark_scan_executing(deep_scan: DeepScan, task_id: str, ingestion_config: IngestionConfig) -> None:
    with SessionLocal() as db:
        scan = db.get(DeepScan, deep_scan.id)
        if not scan:
            return
        scan.task_id = task_id
        scan.state = EXECUTING
        scan.started_at = datetime.now(tz=timezone.utc)
        scan.update_tag = ingestion_config.update_tag
        scan.graph_database = ingestion_config.neo4j_database
        db.commit()


def mark_scan_finished(deep_scan: DeepScan, state: str, ingestion_exceptions: dict[str, Any]) -> None:
    with SessionLocal() as db:
        scan = db.get(DeepScan, deep_scan.id)
        if not scan:
            return
        now = datetime.now(tz=timezone.utc)
        duration = int((now - scan.started_at).total_seconds()) if scan.started_at else 0
        scan.state = state
        scan.progress = 100
        scan.completed_at = now
        scan.duration = duration
        scan.ingestion_exceptions = ingestion_exceptions
        db.commit()


def update_scan_progress(deep_scan: DeepScan, progress: int) -> None:
    with SessionLocal() as db:
        scan = db.get(DeepScan, deep_scan.id)
        if scan:
            scan.progress = progress
            db.commit()


def get_superseded_scans(tenant_id: str, provider_id: str, current_scan_id: str) -> list[DeepScan]:
    with SessionLocal() as db:
        rows = db.scalars(
            select(DeepScan).where(
                DeepScan.tenant_id == int(tenant_id),
                DeepScan.provider_id == int(provider_id),
                DeepScan.state == COMPLETED,
                DeepScan.is_graph_database_deleted.is_(False),
                DeepScan.id != current_scan_id,
            )
        )
        return list(rows)


def mark_old_scan_graph_deleted(old_scan: DeepScan) -> None:
    with SessionLocal() as db:
        scan = db.get(DeepScan, old_scan.id)
        if scan:
            scan.is_graph_database_deleted = True
            db.commit()


def fail_scan_if_stuck(tenant_id: str, scan_id: str, error: str) -> None:
    scan = retrieve_deep_scan(tenant_id, scan_id)
    if scan and scan.state not in (COMPLETED, FAILED):
        mark_scan_finished(scan, FAILED, {"global_error": error})
