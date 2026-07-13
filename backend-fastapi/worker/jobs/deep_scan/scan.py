import os
from types import SimpleNamespace
from typing import Any

from celery import Task

from app.core.database import SessionLocal
from app.db import repositories as repo
from worker.celery_app import celery_app
from worker.jobs.deep_scan.db_utils import COMPLETED, FAILED
from worker.jobs.deep_scan import db_utils
from worker.jobs.deep_scan.config import get_ingestion_function
from worker.jobs.deep_scan.config import get_resource_label
from worker.jobs.deep_scan.config import get_root_node_label
from worker.jobs.deep_scan.config import get_uid_field
from worker.jobs.deep_scan.findings import sync_findings
from worker.jobs.deep_scan.indexes import create_all_indexes
from worker.jobs.deep_scan.internet import sync_internet_exposure
from worker.jobs.deep_scan.sync import sync_graph_to_tenant_db
from worker.jobs.deep_scan.utils import build_ingestion_config
from worker.jobs.deep_scan.utils import get_neo4j_session
from worker.jobs.deep_scan.utils import get_tenant_neo4j_session

DEFAULT_PROVIDER_TYPE = "aws"


class DeepScanTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        tenant_id = kwargs.get("tenant_id") or (args[0] if args else None)
        scan_id = kwargs.get("scan_id") or (args[1] if len(args) > 1 else None)
        if tenant_id and scan_id:
            db_utils.fail_scan_if_stuck(tenant_id, scan_id, str(exc))


@celery_app.task(
    bind=True,
    base=DeepScanTask,
    name="worker.jobs.deep_scan.scan.run",
    max_retries=0,
    acks_late=True,
    track_started=True,
)
def run(self: Task, tenant_id: str, scan_id: str, provider_id: int) -> dict[str, Any]:
    deep_scan = db_utils.retrieve_deep_scan(tenant_id, scan_id)
    if deep_scan is None:
        raise ValueError(f"Scan {scan_id} not found")

    with SessionLocal() as db:
        provider = repo.get_provider(db, deep_scan.provider_id)
    if provider is None:
        raise ValueError(f"Provider {deep_scan.provider_id} not found")

    ingestion_config = build_ingestion_config(deep_scan)
    db_utils.mark_scan_executing(deep_scan, self.request.id, ingestion_config)
    db_utils.update_scan_progress(deep_scan, 2)
    failed_syncs: dict[str, str] = {}
    provider_type = DEFAULT_PROVIDER_TYPE

    try:
        with get_neo4j_session(ingestion_config) as shared_neo4j_session:
            create_all_indexes(shared_neo4j_session)
            ingestion_fn = get_ingestion_function(provider_type)
            failed_syncs = ingestion_fn(
                neo4j_session=shared_neo4j_session,
                ingestion_config=ingestion_config,
                api_provider=provider,
                cloud_provider=_get_cloud_provider(provider),
                deep_scan=deep_scan,
            )
            db_utils.update_scan_progress(deep_scan, 95)
            sync_findings(
                neo4j_session=shared_neo4j_session,
                api_provider=provider,
                deep_scan=deep_scan,
                update_tag=ingestion_config.update_tag,
                root_node_label=get_root_node_label(provider_type),
                resource_label=get_resource_label(provider_type),
                node_uid_field=get_uid_field(provider_type),
            )
            db_utils.update_scan_progress(deep_scan, 96)
            sync_internet_exposure(
                neo4j_session=shared_neo4j_session,
                api_provider=provider,
                update_tag=ingestion_config.update_tag,
                root_node_label=get_root_node_label(provider_type),
            )
            db_utils.update_scan_progress(deep_scan, 97)
            try:
                from worker.jobs.deep_scan.graph_analytics import run_graph_analytics

                flagged = []
                with SessionLocal() as db:
                    from sqlalchemy import select
                    from app.models.orm import Finding

                    flagged = list(
                        db.scalars(
                            select(Finding.arn).where(
                                Finding.provider_id == provider.id,
                                Finding.status.in_(["OPEN", "NEW"]),
                            )
                        ).all()
                    )
                run_graph_analytics(
                    shared_neo4j_session,
                    provider_id=provider.id,
                    update_tag=int(ingestion_config.update_tag),
                    flagged_arns=flagged,
                )
            except Exception as graph_exc:
                import logging

                logging.getLogger(__name__).warning(
                    "Graph analytics failed, scan continues: %s", graph_exc
                )
            from worker.jobs.deep_scan.utils import _build_tenant_neo4j_uri

            tenant_uri = _build_tenant_neo4j_uri(str(deep_scan.tenant_id))
            if tenant_uri != ingestion_config.neo4j_uri:
                with get_tenant_neo4j_session(deep_scan) as tenant_neo4j_session:
                    sync_graph_to_tenant_db(
                        source_session=shared_neo4j_session,
                        dest_session=tenant_neo4j_session,
                        api_provider=provider,
                    )
            db_utils.update_scan_progress(deep_scan, 98)

        _cleanup_old_scans(deep_scan)
        db_utils.update_scan_progress(deep_scan, 99)
        db_utils.mark_scan_finished(deep_scan, COMPLETED, failed_syncs)
        return {"state": COMPLETED, "scan_id": scan_id, "failed_syncs": len(failed_syncs)}
    except Exception as exc:
        db_utils.mark_scan_finished(deep_scan, FAILED, {"global_error": str(exc)})
        raise


def _cleanup_old_scans(deep_scan) -> None:
    old_scans = db_utils.get_superseded_scans(
        tenant_id=deep_scan.tenant_id,
        provider_id=deep_scan.provider_id,
        current_scan_id=deep_scan.id,
    )
    for old_scan in old_scans:
        db_utils.mark_old_scan_graph_deleted(old_scan)


def _get_cloud_provider(provider):
    from worker.jobs.inventory.config import get_session

    region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    boto3_session = get_session(
        account_id=provider.aws_account_id,
        role_name=provider.inventory_role_name,
        region=region,
    )
    session_wrapper = SimpleNamespace(current_session=boto3_session)
    return SimpleNamespace(
        session=session_wrapper,
        _enabled_regions=[region],
        get_global_region=lambda: region,
    )
