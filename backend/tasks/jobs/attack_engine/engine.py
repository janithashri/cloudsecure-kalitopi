from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from tasks.jobs.attack_engine.queries import ATTACK_QUERIES
from tasks.jobs.attack_engine.queries import ATTACK_QUERY_MAP
from tasks.jobs.inventory.neo4j_writer import get_neo4j_driver


def _json_safe(value: Any):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    return str(value)


def _node_id(node: dict[str, Any]) -> str:
    for key in ("id", "arn", "name", "provider_element_id", "groupid", "subnetid"):
        value = node.get(key)
        if value:
            return str(value)
    return str(hash(tuple(sorted(node.items()))))


def _normalize_records(
    records: list[dict[str, Any]], update_tag: int | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    nodes_map: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []

    for rec in records:
        path_nodes: list[str] = []
        for key, value in rec.items():
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, "labels"):
                        props = _json_safe(dict(item))
                        if update_tag is not None and int(props.get("lastupdated", -1)) != int(update_tag):
                            continue
                        labels = list(item.labels)
                        nid = _node_id(props)
                        nodes_map[nid] = {
                            "id": nid,
                            "label": props.get("name") or props.get("id") or (labels[0] if labels else "Node"),
                            "type": labels[0] if labels else "Node",
                            "labels": labels,
                            "properties": props,
                        }
                        path_nodes.append(nid)
            elif hasattr(value, "labels"):
                props = _json_safe(dict(value))
                if update_tag is not None and int(props.get("lastupdated", -1)) != int(update_tag):
                    continue
                labels = list(value.labels)
                nid = _node_id(props)
                nodes_map[nid] = {
                    "id": nid,
                    "label": props.get("name") or props.get("id") or (labels[0] if labels else "Node"),
                    "type": labels[0] if labels else "Node",
                    "labels": labels,
                    "properties": props,
                }
                path_nodes.append(nid)
        if len(path_nodes) > 1:
            for i in range(len(path_nodes) - 1):
                source = path_nodes[i]
                target = path_nodes[i + 1]
                edges.append(
                    {
                        "id": f"{source}->{target}:{len(edges)}",
                        "source": source,
                        "target": target,
                        "relationship": "RELATED_TO",
                    }
                )
        if path_nodes:
            paths.append({"nodes": path_nodes})

    dedup_edges = []
    seen = set()
    for e in edges:
        key = (e["source"], e["target"], e["relationship"])
        if key in seen:
            continue
        seen.add(key)
        dedup_edges.append(e)

    return list(nodes_map.values()), dedup_edges, paths


@contextmanager
def _session_scope(neo4j_session):
    if neo4j_session is not None:
        yield neo4j_session
        return
    driver = get_neo4j_driver()
    with driver.session() as session:
        yield session


def run_attack_query(query_id: str, account_id: str, neo4j_session=None, update_tag: int | None = None) -> dict:
    query = ATTACK_QUERY_MAP.get(query_id)
    if not query:
        return {
            "query_id": query_id,
            "violated": False,
            "node_count": 0,
            "nodes": [],
            "edges": [],
            "paths": [],
            "error": "query_not_found",
        }

    try:
        with _session_scope(neo4j_session) as session:
            records = [dict(r) for r in session.run(query["cypher"], account_id=account_id)]
        nodes, edges, paths = _normalize_records(records, update_tag=update_tag)
        return {
            "query_id": query["id"],
            "name": query["name"],
            "mitre_technique": query["mitre_technique"],
            "mitre_name": query["mitre_name"],
            "mitre_tactic": query["mitre_tactic"],
            "severity": query["severity"],
            "description": query["description"],
            "remediation": query["remediation"],
            "references": query["references"],
            "violated": len(nodes) > 0,
            "node_count": len(nodes),
            "nodes": nodes,
            "edges": edges,
            "paths": paths,
        }
    except Exception as exc:
        return {
            "query_id": query["id"],
            "name": query["name"],
            "mitre_technique": query["mitre_technique"],
            "severity": query["severity"],
            "violated": False,
            "node_count": 0,
            "nodes": [],
            "edges": [],
            "paths": [],
            "error": str(exc),
        }


def run_all_queries(account_id: str, neo4j_session=None, update_tag: int | None = None) -> list[dict]:
    results: list[dict[str, Any]] = []
    for query in ATTACK_QUERIES:
        result = run_attack_query(
            query["id"],
            account_id,
            neo4j_session=neo4j_session,
            update_tag=update_tag,
        )
        results.append(
            {
                "query_id": query["id"],
                "name": query["name"],
                "mitre_technique": query["mitre_technique"],
                "mitre_name": query["mitre_name"],
                "mitre_tactic": query["mitre_tactic"],
                "severity": query["severity"],
                "violated": bool(result.get("violated")),
                "node_count": int(result.get("node_count", 0)),
            }
        )
    return results


def get_attack_graph(query_id: str, account_id: str, neo4j_session=None, update_tag: int | None = None) -> dict:
    result = run_attack_query(
        query_id,
        account_id,
        neo4j_session=neo4j_session,
        update_tag=update_tag,
    )
    if not result.get("violated"):
        return {
            "query_id": query_id,
            "violated": False,
            "nodes": [],
            "edges": [],
            "paths": [],
            "remediation": result.get("remediation"),
        }
    return {
        "query_id": query_id,
        "violated": True,
        "nodes": result.get("nodes", []),
        "edges": result.get("edges", []),
        "paths": result.get("paths", []),
        "remediation": result.get("remediation"),
        "description": result.get("description"),
        "mitre_technique": result.get("mitre_technique"),
        "mitre_name": result.get("mitre_name"),
        "mitre_tactic": result.get("mitre_tactic"),
        "severity": result.get("severity"),
        "name": result.get("name"),
    }
