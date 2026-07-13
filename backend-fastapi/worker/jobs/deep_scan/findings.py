import uuid
from datetime import datetime

import neo4j

from sqlalchemy import select

from app.core.database import SessionLocal
from app.models.orm import DeepScan as DeepScanModel
from app.models.orm import Finding as FindingModel
from app.models.orm import Provider as ProviderModel
from worker.jobs.deep_scan.config import BATCH_SIZE
from worker.jobs.deep_scan.queries import ADD_RESOURCE_LABEL_TEMPLATE
from worker.jobs.deep_scan.queries import CLEANUP_FINDINGS_TEMPLATE
from worker.jobs.deep_scan.queries import INSERT_FINDING_TEMPLATE
from worker.jobs.deep_scan.queries import render_cypher

CLOUDSECURE_VERSION = "1.0.0"


def sync_findings(
    neo4j_session: neo4j.Session,
    api_provider: ProviderModel,
    deep_scan: DeepScanModel,
    update_tag: int,
    root_node_label: str,
    resource_label: str,
    node_uid_field: str,
) -> None:
    query = render_cypher(
        ADD_RESOURCE_LABEL_TEMPLATE,
        {"__ROOT_LABEL__": root_node_label, "__RESOURCE_LABEL__": resource_label},
    )
    while True:
        labeled = neo4j_session.run(query, provider_uid=api_provider.aws_account_id, batch_size=BATCH_SIZE).single()["labeled_count"]
        if labeled == 0:
            break

    insert_query = render_cypher(
        INSERT_FINDING_TEMPLATE,
        {"__ROOT_NODE_LABEL__": root_node_label, "__RESOURCE_LABEL__": resource_label, "__NODE_UID_FIELD__": node_uid_field},
    )
    batch = []
    with SessionLocal() as db:
        findings_qs = db.scalars(
            select(FindingModel).where(FindingModel.provider_id == api_provider.id)
        )
        findings_list = list(findings_qs)
    for finding in findings_list:
        finding = {
            "id": finding.id,
            "arn": finding.arn,
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "severity": finding.severity,
            "status": finding.status,
            "first_seen": finding.first_seen,
            "last_seen": finding.last_seen,
        }
        batch.append(
            {
                "id": str(finding["id"]),
                "uid": str(finding.get("arn") or uuid.uuid4()),
                "inserted_at": _to_iso(finding.get("first_seen")),
                "updated_at": _to_iso(finding.get("last_seen")),
                "first_seen_at": _to_iso(finding.get("first_seen")),
                "scan_id": str(deep_scan.scan_id),
                "delta": None,
                "status": finding.get("status"),
                "status_extended": None,
                "severity": finding.get("severity"),
                "check_id": finding.get("rule_id"),
                "check_title": finding.get("rule_name"),
                "muted": False,
                "muted_reason": None,
                "resource_uid": finding.get("arn"),
            }
        )
        if len(batch) >= BATCH_SIZE:
            neo4j_session.run(insert_query, findings_data=batch, provider_uid=api_provider.aws_account_id, last_updated=update_tag, cloudsecure_version=CLOUDSECURE_VERSION)
            batch = []
    if batch:
        neo4j_session.run(insert_query, findings_data=batch, provider_uid=api_provider.aws_account_id, last_updated=update_tag, cloudsecure_version=CLOUDSECURE_VERSION)

    while True:
        deleted = neo4j_session.run(
            CLEANUP_FINDINGS_TEMPLATE,
            provider_uid=api_provider.aws_account_id,
            last_updated=update_tag,
            batch_size=BATCH_SIZE,
        ).single()["deleted_findings_count"]
        if deleted == 0:
            break


def _to_iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
