import neo4j

from providers.models import Provider as ProviderModel
from tasks.jobs.deep_scan.config import BATCH_SIZE
from tasks.jobs.deep_scan.queries import NODE_FETCH_QUERY
from tasks.jobs.deep_scan.queries import NODE_SYNC_TEMPLATE
from tasks.jobs.deep_scan.queries import RELATIONSHIP_SYNC_TEMPLATE
from tasks.jobs.deep_scan.queries import RELATIONSHIPS_FETCH_QUERY
from tasks.jobs.deep_scan.queries import render_cypher


def sync_graph_to_tenant_db(
    source_session: neo4j.Session,
    dest_session: neo4j.Session,
    api_provider: ProviderModel,
) -> None:
    provider_id = str(api_provider.id)
    _sync_nodes(source_session, dest_session, provider_id)
    _sync_relationships(source_session, dest_session, provider_id)


def _sync_nodes(source_session: neo4j.Session, dest_session: neo4j.Session, provider_id: str) -> int:
    last_id = -1
    total = 0
    while True:
        records = list(source_session.run(NODE_FETCH_QUERY, last_id=last_id, batch_size=BATCH_SIZE))
        if not records:
            break
        rows = []
        for rec in records:
            rows.append(
                {
                    "provider_element_id": rec["element_id"],
                    "props": dict(rec["props"]),
                    "labels": ":".join(rec["labels"]),
                }
            )
        by_labels = {}
        for row in rows:
            by_labels.setdefault(row["labels"], []).append(row)
        for label_str, label_rows in by_labels.items():
            query = render_cypher(NODE_SYNC_TEMPLATE, {"__NODE_LABELS__": label_str})
            dest_session.run(query, rows=label_rows, provider_id=provider_id)
        last_id = records[-1]["internal_id"]
        total += len(records)
    return total


def _sync_relationships(source_session: neo4j.Session, dest_session: neo4j.Session, provider_id: str) -> int:
    last_id = -1
    total = 0
    while True:
        records = list(source_session.run(RELATIONSHIPS_FETCH_QUERY, last_id=last_id, batch_size=BATCH_SIZE))
        if not records:
            break
        by_type = {}
        for rec in records:
            row = {
                "provider_element_id": f"rel_{rec['internal_id']}",
                "start_element_id": rec["start_element_id"],
                "end_element_id": rec["end_element_id"],
                "props": dict(rec["props"]),
            }
            by_type.setdefault(rec["rel_type"], []).append(row)
        for rel_type, rel_rows in by_type.items():
            query = render_cypher(RELATIONSHIP_SYNC_TEMPLATE, {"__REL_TYPE__": rel_type})
            dest_session.run(query, rows=rel_rows, provider_id=provider_id)
        last_id = records[-1]["internal_id"]
        total += len(records)
    return total
