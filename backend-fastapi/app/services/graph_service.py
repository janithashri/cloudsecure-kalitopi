"""Graph and inventory summary helpers (ported from Django api.v1.views)."""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any

import neo4j
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db import repositories as repo
from app.models.orm import DeepScan, Provider
from app.services.neo4j_helpers import build_tenant_neo4j_uri
from worker.jobs.inventory.neo4j_writer import get_neo4j_driver

_tenant_graph_driver_cache: dict[str, neo4j.Driver] = {}


def json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    return str(value)


def short_label_from_arn(arn: str) -> str:
    if not arn:
        return ""
    if ":::" in arn:
        return arn.split(":::")[-1]
    parts = arn.split("/")
    return parts[-1] if parts else arn


def provider_graph_database(db: Session, provider: Provider, scan_id: str | None = None) -> str:
    settings = get_settings()
    if scan_id:
        scan = db.scalar(
            select(DeepScan)
            .where(
                DeepScan.tenant_id == provider.tenant_id,
                DeepScan.provider_id == provider.id,
                DeepScan.scan_id == scan_id,
                DeepScan.is_graph_database_deleted.is_(False),
            )
            .order_by(DeepScan.completed_at.desc(), DeepScan.started_at.desc())
            .limit(1)
        )
        if scan and scan.graph_database:
            return scan.graph_database
    latest = db.scalar(
        select(DeepScan)
        .where(
            DeepScan.tenant_id == provider.tenant_id,
            DeepScan.provider_id == provider.id,
            DeepScan.state == "COMPLETED",
            DeepScan.is_graph_database_deleted.is_(False),
        )
        .order_by(DeepScan.completed_at.desc(), DeepScan.started_at.desc())
        .limit(1)
    )
    if latest and latest.graph_database:
        return latest.graph_database
    return settings.neo4j_shared_database


def provider_scan_update_tag(db: Session, provider: Provider, scan_id: str | None = None) -> int | None:
    if scan_id:
        scan = db.scalar(
            select(DeepScan)
            .where(
                DeepScan.tenant_id == provider.tenant_id,
                DeepScan.provider_id == provider.id,
                DeepScan.scan_id == scan_id,
                DeepScan.is_graph_database_deleted.is_(False),
            )
            .order_by(DeepScan.completed_at.desc(), DeepScan.started_at.desc())
            .limit(1)
        )
        if scan and scan.update_tag is not None:
            return int(scan.update_tag)
    latest = db.scalar(
        select(DeepScan)
        .where(
            DeepScan.tenant_id == provider.tenant_id,
            DeepScan.provider_id == provider.id,
            DeepScan.state == "COMPLETED",
            DeepScan.is_graph_database_deleted.is_(False),
            DeepScan.update_tag.isnot(None),
        )
        .order_by(DeepScan.completed_at.desc(), DeepScan.started_at.desc())
        .limit(1)
    )
    if latest and latest.update_tag is not None:
        return int(latest.update_tag)
    return None


def get_tenant_graph_driver(tenant_id: str) -> neo4j.Driver:
    settings = get_settings()
    tenant_uri = build_tenant_neo4j_uri(tenant_id)
    auth_candidates: list[tuple[str, str]] = []
    if settings.neo4j_tenant_user:
        auth_candidates.append((settings.neo4j_tenant_user, settings.neo4j_tenant_password))
    shared = (settings.resolved_neo4j_shared_user, settings.resolved_neo4j_shared_password)
    if shared not in auth_candidates:
        auth_candidates.append(shared)
    last_exc = None
    for user, password in auth_candidates:
        cache_key = f"{tenant_uri}|{user}"
        if cache_key not in _tenant_graph_driver_cache:
            _tenant_graph_driver_cache[cache_key] = neo4j.GraphDatabase.driver(
                tenant_uri, auth=(user, password)
            )
        driver = _tenant_graph_driver_cache[cache_key]
        try:
            driver.verify_connectivity()
            return driver
        except Exception as exc:
            last_exc = exc
    if last_exc:
        raise last_exc
    raise RuntimeError("Unable to initialize Neo4j tenant graph driver")


@contextmanager
def provider_graph_session(db: Session, provider: Provider, scan_id: str | None = None):
    settings = get_settings()
    database = provider_graph_database(db, provider, scan_id)
    if not settings.neo4j_tenant_uri_template.strip():
        driver = get_neo4j_driver()
        with driver.session(database=database) as session:
            yield session
        return
    driver = get_tenant_graph_driver(str(provider.tenant_id))
    with driver.session(database=database) as session:
        yield session


def inventory_summary(db: Session, provider: Provider) -> dict:
    account_id = provider.aws_account_id
    by_type: dict[str, int] = {}
    total_resources = active_resources = deleted_resources = 0
    try:
        driver = get_neo4j_driver()
        with driver.session() as session:
            rows = session.run(
                """
                MATCH (r:Resource)-[:BELONGS_TO]->(a:AWSAccount {account_id: $account_id})
                RETURN r.type AS type, r.status AS status, count(r) AS count
                """,
                account_id=account_id,
            )
            for row in rows:
                r_type = row.get("type") or "unknown"
                r_status = row.get("status") or "UNKNOWN"
                c = int(row.get("count") or 0)
                by_type[r_type] = by_type.get(r_type, 0) + c
                total_resources += c
                if r_status == "ACTIVE":
                    active_resources += c
                elif r_status == "DELETED":
                    deleted_resources += c
    except Exception:
        by_type = {}
        total_resources = active_resources = deleted_resources = 0

    last_run = repo.get_latest_inventory_run(db, provider.id)
    last_run_payload = None
    if last_run:
        last_run_payload = {
            "state": last_run.state,
            "started_at": last_run.started_at,
            "completed_at": last_run.completed_at,
            "stats": last_run.stats or {},
        }
    return {
        "total_resources": total_resources,
        "by_type": by_type,
        "active_resources": active_resources,
        "deleted_resources": deleted_resources,
        "last_run": last_run_payload,
    }


def inventory_graph_data(
    provider: Provider, type_filter: str | None, status_filter: str | None
) -> dict:
    account_id = provider.aws_account_id
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    nodes[account_id] = {
        "id": account_id,
        "label": account_id,
        "type": "AWSAccount",
        "region": "global",
        "status": "ACTIVE",
        "account_id": account_id,
        "properties": {},
    }
    params = {"account_id": account_id, "type": type_filter, "status": status_filter}
    try:
        driver = get_neo4j_driver()
        with driver.session() as session:
            result = session.run(
                """
                MATCH (r:Resource)-[:BELONGS_TO]->(a:AWSAccount {account_id: $account_id})
                WHERE ($type IS NULL OR r.type = $type)
                  AND ($status IS NULL OR r.status = $status)
                RETURN r, a
                """,
                **params,
            )
            for row in result:
                r = row.get("r")
                if not r:
                    continue
                arn = r.get("arn")
                if not arn:
                    continue
                config_raw = r.get("config") or ""
                try:
                    properties = json.loads(config_raw) if config_raw else {}
                    if not isinstance(properties, dict):
                        properties = {}
                except Exception:
                    properties = {}
                nodes[arn] = {
                    "id": arn,
                    "label": short_label_from_arn(arn),
                    "type": r.get("type"),
                    "region": r.get("region"),
                    "status": r.get("status") or "UNKNOWN",
                    "account_id": account_id,
                    "properties": properties,
                }
            for node_id, node in list(nodes.items()):
                if node.get("type") == "AWSAccount":
                    continue
                edges.append(
                    {
                        "id": f"edge-belongs-{node_id}",
                        "source": node_id,
                        "target": account_id,
                        "relationship": "BELONGS_TO",
                    }
                )
            rel_rows = session.run(
                """
                MATCH (r:Resource)-[:BELONGS_TO]->(a:AWSAccount {account_id: $account_id})
                WHERE ($type IS NULL OR r.type = $type)
                  AND ($status IS NULL OR r.status = $status)
                MATCH (r)-[rel]->(target)
                WHERE r.arn STARTS WITH 'arn:aws'
                RETURN r.arn AS source,
                       coalesce(target.arn, target.account_id, target.vpc_id, target.group_id) AS target,
                       type(rel) AS relationship
                """,
                **params,
            )
            for i, row in enumerate(rel_rows):
                source, target, relationship = row.get("source"), row.get("target"), row.get("relationship")
                if source and target and relationship:
                    edges.append(
                        {
                            "id": f"edge-{i}",
                            "source": source,
                            "target": target,
                            "relationship": relationship,
                        }
                    )
    except Exception:
        return {"nodes": [], "edges": []}
    return {"nodes": list(nodes.values()), "edges": edges}


def cartography_graph_data(
    db: Session, provider: Provider, label_filter: str | None, scan_id: str | None
) -> dict:
    update_tag = provider_scan_update_tag(db, provider, scan_id)
    if update_tag is None:
        return {"nodes": [], "edges": []}

    def graph_node_id(props: dict) -> str:
        for key in ("id", "arn", "name", "provider_element_id", "groupid", "subnetid"):
            if props.get(key):
                return str(props[key])
        return str(hash(tuple(sorted(props.items()))))

    def graph_node_label(props: dict, labels: list[str]) -> str:
        raw = str(props.get("name") or props.get("id") or props.get("arn") or (labels[0] if labels else "Node"))
        if raw.startswith("arn:"):
            return (raw.split("/")[-1] if "/" in raw else raw.split(":")[-1]) or raw
        return raw

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    edge_seen: set[tuple[str, str, str]] = set()
    try:
        with provider_graph_session(db, provider, scan_id) as session:
            node_query = """
                MATCH (n)
                WHERE toInteger(coalesce(n.lastupdated, -1)) = toInteger($update_tag)
                  AND ($label IS NULL OR any(l IN labels(n) WHERE l = $label))
                RETURN n LIMIT 4000
            """
            for row in session.run(node_query, label=label_filter, update_tag=update_tag):
                node = row.get("n")
                if node is None:
                    continue
                props = json_safe(dict(node))
                labels = list(node.labels)
                node_id = graph_node_id(props)
                nodes[node_id] = {
                    "id": node_id,
                    "label": graph_node_label(props, labels),
                    "type": labels[0] if labels else "Node",
                    "labels": labels,
                    "properties": props,
                }
            rel_query = """
                MATCH (n)-[r]->(m)
                WHERE toInteger(coalesce(r.lastupdated, -1)) = toInteger($update_tag)
                  AND toInteger(coalesce(n.lastupdated, -1)) = toInteger($update_tag)
                  AND toInteger(coalesce(m.lastupdated, -1)) = toInteger($update_tag)
                  AND ($label IS NULL OR any(l IN labels(n) WHERE l = $label) OR any(l IN labels(m) WHERE l = $label))
                RETURN n, r, m LIMIT 8000
            """
            for i, row in enumerate(session.run(rel_query, label=label_filter, update_tag=update_tag)):
                n, m, r = row.get("n"), row.get("m"), row.get("r")
                if n is None or m is None or r is None:
                    continue
                n_props, m_props = json_safe(dict(n)), json_safe(dict(m))
                n_labels, m_labels = list(n.labels), list(m.labels)
                source, target = graph_node_id(n_props), graph_node_id(m_props)
                for nid, nprops, nlabels in ((source, n_props, n_labels), (target, m_props, m_labels)):
                    if nid not in nodes:
                        nodes[nid] = {
                            "id": nid,
                            "label": graph_node_label(nprops, nlabels),
                            "type": nlabels[0] if nlabels else "Node",
                            "labels": nlabels,
                            "properties": nprops,
                        }
                rel_type = str(r.type)
                edge_key = (source, target, rel_type)
                if edge_key in edge_seen:
                    continue
                edge_seen.add(edge_key)
                edges.append(
                    {
                        "id": f"edge-{i}-{source}-{target}-{rel_type}",
                        "source": source,
                        "target": target,
                        "relationship": rel_type,
                    }
                )
    except Exception as exc:
        return {"nodes": [], "edges": [], "error": str(exc)}
    return {"nodes": list(nodes.values()), "edges": edges}
