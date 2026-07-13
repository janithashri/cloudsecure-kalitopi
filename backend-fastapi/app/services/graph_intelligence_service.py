from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.orm import DeepScan, Finding, Provider
from app.services.graph_service import provider_graph_session, provider_scan_update_tag
from worker.jobs.inventory.neo4j_writer import get_neo4j_driver
from worker.jobs.deep_scan.graph_analytics import (
    build_id_to_arn_map,
    compute_adjusted_severity,
    gds_available,
)

logger = logging.getLogger(__name__)


def _check_gds_available() -> bool:
    from app.core.config import get_settings

    settings = get_settings()
    try:
        driver = get_neo4j_driver()
        with driver.session(database=settings.neo4j_shared_database) as session:
            return gds_available(session)
    except Exception as exc:
        logger.warning("[Graph Intelligence API] GDS check failed: %s", exc)
        return False


def _last_completed_scan(db: Session, provider: Provider) -> DeepScan | None:
    return db.scalar(
        select(DeepScan)
        .where(
            DeepScan.provider_id == provider.id,
            DeepScan.tenant_id == provider.tenant_id,
            DeepScan.state == "COMPLETED",
        )
        .order_by(DeepScan.completed_at.desc())
        .limit(1)
    )


def get_graph_intelligence(db: Session, provider: Provider) -> dict[str, Any]:
    findings_qs = db.scalars(
        select(Finding).where(
            Finding.provider_id == provider.id,
            Finding.status.in_(["OPEN", "NEW"]),
        )
    ).all()

    arn_to_finding = {f.arn: f for f in findings_qs}
    id_to_arn = build_id_to_arn_map(list(arn_to_finding.keys()))
    lookup_keys = list(id_to_arn.keys())

    high_risk_nodes: list[dict[str, Any]] = []
    shadow_risks: list[dict[str, Any]] = []
    gds_ok = _check_gds_available()
    last_run_timestamp = None

    last_scan = _last_completed_scan(db, provider)
    if last_scan and last_scan.completed_at:
        last_run_timestamp = last_scan.completed_at.isoformat()

    update_tag = provider_scan_update_tag(db, provider)
    if update_tag is None:
        return {
            "high_risk_nodes": [],
            "shadow_risks": [],
            "summary": {
                "total_high_risk_nodes": 0,
                "total_escalated": 0,
                "total_shadow_risks": 0,
                "most_dangerous_node_arn": "",
                "gds_available": gds_ok,
                "last_run_timestamp": last_run_timestamp,
            },
        }

    try:
        with provider_graph_session(db, provider) as session:
            if not gds_ok:
                gds_ok = gds_available(session)

            neo4j_nodes = session.run(
                """
                MATCH (n)
                WHERE (
                    n.id IN $lookup_keys OR n.arn IN $lookup_keys OR n.ARN IN $lookup_keys
                )
                  AND n.pagerank_score IS NOT NULL
                  AND NOT (n.id IS NOT NULL AND n.id CONTAINS '/')
                RETURN
                    coalesce(n.id, n.arn, n.ARN) AS node_id,
                    labels(n)[0] AS label,
                    coalesce(n.pagerank_score, 0.0) AS pagerank_score,
                    coalesce(n.betweenness_score, 0.0) AS betweenness_score,
                    coalesce(n.hops_from_internet, 99) AS hops_from_internet,
                    coalesce(n.community_size, 0) AS community_size,
                    coalesce(n.core_value, 0) AS core_value,
                    coalesce(n.is_bridge, false) AS is_bridge
                """,
                lookup_keys=lookup_keys or [""],
            ).data()

            for node in neo4j_nodes:
                node_id = node.get("node_id", "")
                original_arn = id_to_arn.get(node_id, node_id)
                finding = arn_to_finding.get(original_arn)
                if not finding:
                    finding = arn_to_finding.get(node_id)
                    if finding:
                        original_arn = node_id

                original_severity = finding.severity if finding else "LOW"
                graph_scores = {
                    "pagerank_score": node.get("pagerank_score", 0.0),
                    "betweenness_score": node.get("betweenness_score", 0.0),
                    "hops_from_internet": node.get("hops_from_internet", 99),
                    "community_size": node.get("community_size", 0),
                    "core_value": node.get("core_value", 0),
                    "is_bridge": node.get("is_bridge", False),
                }
                adjusted, reasons = compute_adjusted_severity(original_severity, graph_scores)
                high_risk_nodes.append(
                    {
                        "arn": original_arn,
                        "resource_type": (finding.resource_type if finding else None) or node.get("label", ""),
                        "original_severity": original_severity,
                        "graph_adjusted_severity": adjusted,
                        "escalation_reasons": reasons,
                        "pagerank_score": graph_scores["pagerank_score"],
                        "betweenness_score": graph_scores["betweenness_score"],
                        "hops_from_internet": graph_scores["hops_from_internet"],
                        "community_size": graph_scores["community_size"],
                        "core_value": graph_scores["core_value"],
                        "is_bridge": graph_scores["is_bridge"],
                        "rule_id": finding.rule_id if finding else "",
                        "rule_name": finding.rule_name if finding else "",
                    }
                )

            shadow_rows = session.run(
                """
                MATCH (n)
                WHERE n.violation_similarity_score >= 0.75
                  AND NOT (
                    n.id IN $lookup_keys OR n.arn IN $lookup_keys OR n.ARN IN $lookup_keys
                  )
                  AND NOT (n.id IS NOT NULL AND n.id CONTAINS '/')
                RETURN
                    coalesce(n.id, n.arn, n.ARN) AS node_id,
                    labels(n)[0] AS label,
                    n.violation_similarity_score AS violation_similarity_score,
                    coalesce(n.matched_rule_id, '') AS matched_rule_id,
                    coalesce(n.matched_resource_arn, '') AS matched_resource_arn,
                    coalesce(n.matching_attributes, []) AS matching_attributes
                """,
                lookup_keys=lookup_keys or [""],
            ).data()

            for row in shadow_rows:
                shadow_risks.append(
                    {
                        "arn": row.get("node_id", ""),
                        "resource_type": row.get("label", ""),
                        "violation_similarity_score": row.get("violation_similarity_score", 0),
                        "matched_rule_id": row.get("matched_rule_id", ""),
                        "matched_resource_arn": row.get("matched_resource_arn", ""),
                        "matching_attributes": row.get("matching_attributes", []),
                    }
                )
    except Exception as exc:
        logger.warning("[Graph Intelligence API] Neo4j read failed: %s", exc)
        gds_ok = False

    escalated = [n for n in high_risk_nodes if n["graph_adjusted_severity"] != n["original_severity"]]
    most_dangerous_arn = ""
    if high_risk_nodes:
        pool = escalated if escalated else high_risk_nodes
        most_dangerous_arn = max(pool, key=lambda n: n["pagerank_score"])["arn"]

    return {
        "high_risk_nodes": high_risk_nodes,
        "shadow_risks": shadow_risks,
        "summary": {
            "total_high_risk_nodes": len(high_risk_nodes),
            "total_escalated": len(escalated),
            "total_shadow_risks": len(shadow_risks),
            "most_dangerous_node_arn": most_dangerous_arn,
            "gds_available": gds_ok,
            "last_run_timestamp": last_run_timestamp,
        },
    }
