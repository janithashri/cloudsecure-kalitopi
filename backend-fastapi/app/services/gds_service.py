from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from fastapi import HTTPException
from neo4j import Session
from sqlalchemy.orm import Session as DBSession

from app.models.orm import Provider
from app.services.graph_service import provider_graph_database, provider_scan_update_tag, provider_graph_session


@dataclass
class ProjectionHandle:
    graph_name: str
    dropped: bool = False


def ensure_gds_available(session: Session) -> None:
    try:
        session.run("CALL gds.version() YIELD version RETURN version").single()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Neo4j GDS plugin not available: {exc}") from exc


def _projection_query() -> str:
    return """
        CALL gds.graph.project.cypher(
            $graph_name,
            'MATCH (n) WHERE toInteger(coalesce(n.lastupdated, -1)) = toInteger($update_tag)
             RETURN id(n) AS id',
            'MATCH (a)-[r]->(b)
             WHERE toInteger(coalesce(a.lastupdated, -1)) = toInteger($update_tag)
               AND toInteger(coalesce(r.lastupdated, -1)) = toInteger($update_tag)
               AND toInteger(coalesce(b.lastupdated, -1)) = toInteger($update_tag)
             RETURN id(a) AS source, id(b) AS target, 1.0 AS weight',
            {parameters: {update_tag: $update_tag}}
        )
        YIELD graphName, nodeCount, relationshipCount
        RETURN graphName, nodeCount, relationshipCount
    """


def create_projection(session: Session, provider: Provider, update_tag: int) -> ProjectionHandle:
    graph_name = f"cs_{provider.tenant_id}_{provider.id}_{update_tag}_{uuid4().hex[:8]}"
    try:
        session.run(_projection_query(), graph_name=graph_name, update_tag=update_tag).single()
        return ProjectionHandle(graph_name=graph_name)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"GDS projection creation failed: {exc}") from exc


def drop_projection(session: Session, handle: ProjectionHandle) -> None:
    if handle.dropped:
        return
    try:
        session.run("CALL gds.graph.drop($graph_name, false)", graph_name=handle.graph_name).consume()
    except Exception:
        pass
    handle.dropped = True


def shortest_path(
    db: DBSession,
    provider: Provider,
    source_node_id: str,
    target_node_id: str,
    scan_id: str | None = None,
) -> dict:
    update_tag = provider_scan_update_tag(db, provider, scan_id)
    if update_tag is None:
        raise HTTPException(status_code=409, detail="Deep scan is required before running GDS shortest path")

    with provider_graph_session(db, provider, scan_id) as session:
        ensure_gds_available(session)
        handle = create_projection(session, provider, update_tag)
        try:
            query = """
                MATCH (source) WHERE coalesce(source.id, source.arn, source.name, source.provider_element_id) = $source_id
                MATCH (target) WHERE coalesce(target.id, target.arn, target.name, target.provider_element_id) = $target_id
                CALL gds.shortestPath.dijkstra.stream($graph_name, {
                    sourceNode: id(source),
                    targetNode: id(target),
                    relationshipWeightProperty: 'weight'
                })
                YIELD totalCost, nodeIds, costs, path
                RETURN totalCost, nodeIds, costs,
                       [n IN nodes(path) | {
                           node_id: coalesce(n.id, n.arn, n.name, n.provider_element_id, toString(id(n))),
                           labels: labels(n),
                           properties: properties(n)
                       }] AS nodes
                LIMIT 1
            """
            row = session.run(
                query,
                graph_name=handle.graph_name,
                source_id=source_node_id,
                target_id=target_node_id,
            ).single()
            if row is None:
                raise HTTPException(status_code=404, detail="No path found between given nodes")
            nodes = row.get("nodes") or []
            costs = row.get("costs") or []
            for idx, node in enumerate(nodes):
                if idx < len(costs):
                    node["cost_to_reach"] = float(costs[idx])
            return {
                "graph_name": handle.graph_name,
                "source_node_id": source_node_id,
                "target_node_id": target_node_id,
                "total_cost": float(row.get("totalCost") or 0.0),
                "node_count": len(nodes),
                "relationship_count": max(len(nodes) - 1, 0),
                "nodes": nodes,
            }
        finally:
            drop_projection(session, handle)
