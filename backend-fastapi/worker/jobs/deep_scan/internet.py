import neo4j

from app.models.orm import Provider as ProviderModel
from worker.jobs.deep_scan.queries import CREATE_INTERNET_ACCESS_EDGES_TEMPLATE
from worker.jobs.deep_scan.queries import CREATE_INTERNET_NODE
from worker.jobs.deep_scan.queries import render_cypher

CLOUDSECURE_VERSION = "1.0.0"


def sync_internet_exposure(
    neo4j_session: neo4j.Session,
    api_provider: ProviderModel,
    update_tag: int,
    root_node_label: str,
) -> None:
    neo4j_session.run(
        CREATE_INTERNET_NODE,
        last_updated=update_tag,
        cloudsecure_version=CLOUDSECURE_VERSION,
    )
    query = render_cypher(
        CREATE_INTERNET_ACCESS_EDGES_TEMPLATE, {"__ROOT_LABEL__": root_node_label}
    )
    neo4j_session.run(
        query,
        provider_uid=api_provider.aws_account_id,
        last_updated=update_tag,
        cloudsecure_version=CLOUDSECURE_VERSION,
    )
