from __future__ import annotations

import logging
import os

from cartography.config import Config as IngestionConfig
from sqlalchemy import select

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.orm import DeepScan, Finding
from worker.celery_app import celery_app
from worker.jobs.deep_scan.graph_analytics import run_graph_analytics
from worker.jobs.deep_scan.utils import get_neo4j_session

logger = logging.getLogger(__name__)


def _neo4j_config(update_tag: int) -> IngestionConfig:
    settings = get_settings()
    return IngestionConfig(
        neo4j_uri=settings.resolved_neo4j_shared_uri,
        neo4j_user=settings.resolved_neo4j_shared_user,
        neo4j_password=settings.resolved_neo4j_shared_password,
        neo4j_database=settings.neo4j_shared_database,
        update_tag=update_tag,
        permission_relationships_file=settings.cartography_permission_relationships_file,
        aws_best_effort_mode=True,
        aws_guardduty_severity_threshold=os.environ.get("AWS_GUARDDUTY_SEVERITY_THRESHOLD", "MEDIUM"),
        aws_cloudtrail_management_events_lookback_hours=int(
            os.environ.get("AWS_CLOUDTRAIL_LOOKBACK_HOURS", "24")
        ),
        experimental_aws_inspector_batch=os.environ.get("AWS_INSPECTOR_BATCH_EXPERIMENTAL", "false").lower()
        in ("1", "true", "yes"),
    )


@celery_app.task(
    name="worker.jobs.deep_scan.graph_analytics.run",
    queue="deep_scan",
    acks_late=True,
)
def run_graph_analytics_task(provider_id: int, deep_scan_id: str, tenant_id: int):
    with SessionLocal() as db:
        scan = db.scalar(
            select(DeepScan).where(
                DeepScan.scan_id == deep_scan_id,
                DeepScan.provider_id == provider_id,
                DeepScan.tenant_id == tenant_id,
            )
        )
        if scan is None or scan.update_tag is None:
            logger.warning("Graph analytics skipped: scan %s missing or has no update_tag", deep_scan_id)
            return {"status": "skipped"}

        flagged = list(
            db.scalars(
                select(Finding.arn).where(
                    Finding.provider_id == provider_id,
                    Finding.status.in_(["OPEN", "NEW"]),
                )
            ).all()
        )

        with get_neo4j_session(_neo4j_config(int(scan.update_tag))) as session:
            return run_graph_analytics(
                session,
                provider_id=provider_id,
                update_tag=int(scan.update_tag),
                flagged_arns=flagged,
            )
