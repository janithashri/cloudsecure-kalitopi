"""Neo4j GDS analytics: write graph scores to nodes after deep scan."""

from __future__ import annotations

import logging
from typing import Any

from neo4j import Session

logger = logging.getLogger(__name__)

PROJECTION_PREFIX = "cloudsecure-gi"
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def gds_available(session: Session) -> bool:
    try:
        session.run("CALL gds.list() YIELD name RETURN name LIMIT 1").consume()
        return True
    except Exception:
        return False


def compute_adjusted_severity(
    base_severity: str,
    graph_scores: dict[str, Any],
) -> tuple[str, list[str]]:
    try:
        idx = SEVERITY_ORDER.index(base_severity.upper())
    except ValueError:
        idx = SEVERITY_ORDER.index("LOW")

    reasons: list[str] = []
    if float(graph_scores.get("pagerank_score") or 0) > 0.7:
        idx += 1
        reasons.append("high_centrality")
    if float(graph_scores.get("betweenness_score") or 0) > 500:
        idx += 1
        reasons.append("chokepoint")
    if int(graph_scores.get("hops_from_internet") or 99) <= 2:
        idx += 1
        reasons.append("internet_exposed")
    if int(graph_scores.get("community_size") or 0) > 5:
        idx += 1
        reasons.append("large_blast_radius")
    if int(graph_scores.get("core_value") or 0) >= 3:
        idx += 1
        reasons.append("dense_zone")
    if bool(graph_scores.get("is_bridge")):
        idx += 1
        reasons.append("bridge_node")

    adjusted = SEVERITY_ORDER[min(idx, len(SEVERITY_ORDER) - 1)]
    return adjusted, reasons


def _projection_name(provider_id: int | str, update_tag: int) -> str:
    return f"{PROJECTION_PREFIX}-{provider_id}-{update_tag}"


def _drop_projection(session: Session, name: str) -> None:
    try:
        session.run("CALL gds.graph.drop($name, false)", name=name).consume()
    except Exception:
        pass


def _project_graph(session: Session, name: str, update_tag: int) -> None:
    _drop_projection(session, name)
    session.run(
        """
        CALL gds.graph.project.cypher(
            $graph_name,
            'MATCH (n) WHERE toInteger(coalesce(n.lastupdated, -1)) = toInteger($update_tag)
             AND n.id IS NOT NULL AND NOT n.id CONTAINS "/"
             RETURN id(n) AS id',
            'MATCH (a)-[r]->(b)
             WHERE toInteger(coalesce(a.lastupdated, -1)) = toInteger($update_tag)
               AND toInteger(coalesce(r.lastupdated, -1)) = toInteger($update_tag)
               AND toInteger(coalesce(b.lastupdated, -1)) = toInteger($update_tag)
               AND a.id IS NOT NULL AND NOT a.id CONTAINS "/"
               AND b.id IS NOT NULL AND NOT b.id CONTAINS "/"
             RETURN id(a) AS source, id(b) AS target',
            {parameters: {update_tag: $update_tag}}
        )
        YIELD graphName, nodeCount, relationshipCount
        RETURN graphName, nodeCount, relationshipCount
        """,
        graph_name=name,
        update_tag=int(update_tag),
    ).consume()


def _run_pagerank(session: Session, name: str) -> None:
    session.run(
        """
        CALL gds.pageRank.write($name, {
            writeProperty: 'pagerank_score',
            maxIterations: 20,
            dampingFactor: 0.85
        })
        YIELD nodePropertiesWritten
        """,
        name=name,
    ).consume()


def _run_betweenness(session: Session, name: str) -> None:
    session.run(
        """
        CALL gds.betweenness.write($name, {writeProperty: 'betweenness_score'})
        YIELD nodePropertiesWritten
        """,
        name=name,
    ).consume()


def _run_louvain(session: Session, name: str, update_tag: int) -> None:
    session.run(
        """
        CALL gds.louvain.write($name, {writeProperty: 'community_id'})
        YIELD nodePropertiesWritten
        """,
        name=name,
    ).consume()
    session.run(
        """
        MATCH (n)
        WHERE toInteger(coalesce(n.lastupdated, -1)) = toInteger($update_tag)
          AND n.community_id IS NOT NULL
        WITH n.community_id AS cid, count(*) AS sz
        MATCH (m)
        WHERE toInteger(coalesce(m.lastupdated, -1)) = toInteger($update_tag)
          AND m.community_id = cid
        SET m.community_size = sz
        """,
        update_tag=update_tag,
    ).consume()


def _run_kcore(session: Session, name: str, update_tag: int) -> None:
    try:
        session.run(
            """
            CALL gds.kcore.write($name, {writeProperty: 'core_value'})
            YIELD nodePropertiesWritten
            """,
            name=name,
        ).consume()
    except Exception as exc:
        logger.warning("[Graph Analytics] k-core skipped: %s", exc)
        session.run(
            """
            MATCH (n)
            WHERE toInteger(coalesce(n.lastupdated, -1)) = toInteger($update_tag)
            SET n.core_value = coalesce(n.core_value, 0)
            """,
            update_tag=update_tag,
        ).consume()


def _run_wcc_and_bridges(session: Session, name: str, update_tag: int) -> None:
    session.run(
        """
        CALL gds.wcc.write($name, {writeProperty: 'component_id'})
        YIELD nodePropertiesWritten
        """,
        name=name,
    ).consume()
    session.run(
        """
        MATCH (n)-[]-(m)
        WHERE toInteger(coalesce(n.lastupdated, -1)) = toInteger($update_tag)
          AND toInteger(coalesce(m.lastupdated, -1)) = toInteger($update_tag)
          AND n.component_id IS NOT NULL AND m.component_id IS NOT NULL
        WITH n, collect(DISTINCT m.component_id) AS neighbor_components
        SET n.is_bridge = size(neighbor_components) > 1
        """,
        update_tag=update_tag,
    ).consume()
    session.run(
        """
        MATCH (n)
        WHERE toInteger(coalesce(n.lastupdated, -1)) = toInteger($update_tag)
          AND n.is_bridge IS NULL
        SET n.is_bridge = false
        """,
        update_tag=update_tag,
    ).consume()


def _run_internet_hops(session: Session, name: str, update_tag: int) -> None:
    session.run(
        """
        MATCH (n)
        WHERE toInteger(coalesce(n.lastupdated, -1)) = toInteger($update_tag)
          AND NOT n:Internet
          AND n.id IS NOT NULL AND NOT n.id CONTAINS '/'
        SET n.hops_from_internet = 99
        """,
        update_tag=update_tag,
    ).consume()
    rows = session.run(
        """
        MATCH (internet:Internet)
        WHERE toInteger(coalesce(internet.lastupdated, -1)) = toInteger($update_tag)
        RETURN id(internet) AS internet_id
        LIMIT 20
        """,
        update_tag=update_tag,
    ).data()
    if not rows:
        return
    for row in rows:
        internet_id = row["internet_id"]
        session.run(
            """
            MATCH (target)
            WHERE toInteger(coalesce(target.lastupdated, -1)) = toInteger($update_tag)
              AND NOT target:Internet
              AND target.id IS NOT NULL AND NOT target.id CONTAINS '/'
            CALL gds.shortestPath.dijkstra.stream($name, {
                sourceNode: $internet_id,
                targetNode: id(target)
            })
            YIELD totalCost
            SET target.hops_from_internet = toInteger(totalCost)
            """,
            name=name,
            update_tag=update_tag,
            internet_id=internet_id,
        ).consume()


def _run_shadow_scoring(session: Session, update_tag: int, flagged_keys: list[str]) -> None:
    session.run(
        """
        MATCH (n)
        WHERE toInteger(coalesce(n.lastupdated, -1)) = toInteger($update_tag)
          AND n.pagerank_score IS NOT NULL
          AND NOT (
            n.id IN $lookup_keys OR n.arn IN $lookup_keys OR n.ARN IN $lookup_keys
          )
          AND NOT (n.id IS NOT NULL AND n.id CONTAINS '/')
        WITH n,
             coalesce(n.pagerank_score, 0.0) AS pr,
             coalesce(n.hops_from_internet, 99) AS hops,
             coalesce(n.is_bridge, false) AS bridge
        WITH n,
             CASE WHEN hops <= 2 THEN 0.35 ELSE 0.0 END +
             CASE WHEN pr > 0.7 THEN 0.45 ELSE pr * 0.45 END +
             CASE WHEN bridge THEN 0.2 ELSE 0.0 END AS score
        WHERE score >= 0.75
        SET n.violation_similarity_score = score,
            n.matched_rule_id = coalesce(n.matched_rule_id, ''),
            n.matched_resource_arn = coalesce(n.matched_resource_arn, ''),
            n.matching_attributes = coalesce(n.matching_attributes, [])
        """,
        update_tag=update_tag,
        lookup_keys=flagged_keys or [""],
    ).consume()


def run_graph_analytics(
    session: Session,
    provider_id: int | str,
    update_tag: int,
    flagged_arns: list[str] | None = None,
) -> dict[str, Any]:
    if not gds_available(session):
        logger.warning("[Graph Analytics] GDS plugin not available")
        return {"gds_available": False}

    projection = _projection_name(provider_id, update_tag)
    lookup_keys = _build_lookup_keys(flagged_arns or [])
    errors: list[str] = []

    def step(label: str, fn) -> None:
        try:
            fn()
        except Exception as exc:
            logger.warning("[Graph Analytics] %s failed: %s", label, exc, exc_info=True)
            errors.append(f"{label}: {exc}")

    try:
        logger.info("[Graph Analytics] projecting graph for provider %s tag %s", provider_id, update_tag)
        step("project", lambda: _project_graph(session, projection, update_tag))
        step("pagerank", lambda: _run_pagerank(session, projection))
        step("betweenness", lambda: _run_betweenness(session, projection))
        step("louvain", lambda: _run_louvain(session, projection, update_tag))
        step("kcore", lambda: _run_kcore(session, projection, update_tag))
        step("wcc_bridges", lambda: _run_wcc_and_bridges(session, projection, update_tag))
        step("internet_hops", lambda: _run_internet_hops(session, projection, update_tag))
        _drop_projection(session, projection)
        step("shadow_scoring", lambda: _run_shadow_scoring(session, update_tag, lookup_keys))
        if errors:
            logger.warning(
                "[Graph Analytics] finished with %s error(s) for provider %s",
                len(errors),
                provider_id,
            )
            return {"gds_available": True, "update_tag": update_tag, "errors": errors}
        logger.info("[Graph Analytics] completed for provider %s", provider_id)
        return {"gds_available": True, "update_tag": update_tag}
    except Exception as exc:
        logger.warning("[Graph Analytics] failed: %s", exc, exc_info=True)
        _drop_projection(session, projection)
        return {"gds_available": True, "error": str(exc)}


def extract_resource_id(arn: str) -> str:
    parts = arn.split(":")
    if len(parts) < 6:
        return arn
    resource = parts[-1]
    if "/" in resource:
        return resource.split("/")[-1]
    return resource or arn


def build_id_to_arn_map(arns: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for arn in arns:
        mapping[arn] = arn
        short_id = extract_resource_id(arn)
        if short_id != arn:
            mapping[short_id] = arn
    return mapping


def _build_lookup_keys(arns: list[str]) -> list[str]:
    keys: set[str] = set()
    for arn in arns:
        keys.add(arn)
        keys.add(extract_resource_id(arn))
    return list(keys)
