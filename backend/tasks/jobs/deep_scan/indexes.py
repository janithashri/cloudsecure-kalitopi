from enum import Enum

import neo4j
from cartography.client.core.tx import run_write_query

from tasks.jobs.deep_scan.config import CLOUDSECURE_FINDING_LABEL
from tasks.jobs.deep_scan.config import INTERNET_NODE_LABEL
from tasks.jobs.deep_scan.config import PROVIDER_RESOURCE_LABEL


class IndexType(Enum):
    FINDINGS = "findings"
    SYNC = "sync"


FINDINGS_INDEX_STATEMENTS = [
    "CREATE INDEX aws_resource_arn IF NOT EXISTS FOR (n:AWSResource) ON (n.arn);",
    "CREATE INDEX aws_resource_id IF NOT EXISTS FOR (n:AWSResource) ON (n.id);",
    f"CREATE INDEX cs_finding_id IF NOT EXISTS FOR (n:{CLOUDSECURE_FINDING_LABEL}) ON (n.id);",
    f"CREATE INDEX cs_finding_provider_uid IF NOT EXISTS FOR (n:{CLOUDSECURE_FINDING_LABEL}) ON (n.provider_uid);",
    f"CREATE INDEX cs_finding_lastupdated IF NOT EXISTS FOR (n:{CLOUDSECURE_FINDING_LABEL}) ON (n.lastupdated);",
    f"CREATE INDEX cs_finding_status IF NOT EXISTS FOR (n:{CLOUDSECURE_FINDING_LABEL}) ON (n.status);",
    f"CREATE INDEX internet_id IF NOT EXISTS FOR (n:{INTERNET_NODE_LABEL}) ON (n.id);",
]

SYNC_INDEX_STATEMENTS = [
    f"CREATE INDEX provider_element_id IF NOT EXISTS FOR (n:{PROVIDER_RESOURCE_LABEL}) ON (n.provider_element_id);",
    f"CREATE INDEX provider_resource_provider_id IF NOT EXISTS FOR (n:{PROVIDER_RESOURCE_LABEL}) ON (n.provider_id);",
]


def create_indexes(neo4j_session: neo4j.Session, index_type: IndexType) -> None:
    if index_type == IndexType.FINDINGS:
        for stmt in FINDINGS_INDEX_STATEMENTS:
            run_write_query(neo4j_session, stmt)
    elif index_type == IndexType.SYNC:
        for stmt in SYNC_INDEX_STATEMENTS:
            neo4j_session.run(stmt)


def create_all_indexes(neo4j_session: neo4j.Session) -> None:
    create_indexes(neo4j_session, IndexType.FINDINGS)
    create_indexes(neo4j_session, IndexType.SYNC)
