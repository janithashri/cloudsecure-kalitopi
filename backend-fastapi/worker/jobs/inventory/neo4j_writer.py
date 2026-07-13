import json
import logging
from functools import lru_cache

import neo4j

from app.core.config import get_settings

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_neo4j_driver():
    settings = get_settings()
    uri = settings.resolved_neo4j_shared_uri
    if not uri:
        raise ValueError(
            "Neo4j is not configured. Set NEO4J_URI (e.g. neo4j+s://xxx.databases.neo4j.io) in .env"
        )
    return neo4j.GraphDatabase.driver(
        uri,
        auth=(settings.resolved_neo4j_shared_user, settings.resolved_neo4j_shared_password),
    )


def write_resource_to_neo4j(driver, account_id: str, resource: dict):
    config_json = json.dumps(resource.get("config") or {})
    tags_json = json.dumps(resource.get("tags") or {})
    settings = get_settings()
    with driver.session(database=settings.neo4j_shared_database) as session:
        session.run(
            """
            MERGE (a:AWSAccount {account_id: $account_id})
            MERGE (r:Resource {arn: $arn})
            SET r.type = $type,
                r.region = $region,
                r.status = 'ACTIVE',
                r.config = $config,
                r.tags = $tags,
                r.updated_at = datetime()
            MERGE (r)-[:BELONGS_TO]->(a)
            """,
            account_id=account_id,
            arn=resource["arn"],
            type=resource.get("type"),
            region=resource.get("region"),
            config=config_json,
            tags=tags_json,
        )


def tombstone_resource(driver, arn: str):
    settings = get_settings()
    with driver.session(database=settings.neo4j_shared_database) as session:
        session.run(
            """
            MATCH (r:Resource {arn: $arn})
            SET r.status = 'DELETED', r.updated_at = datetime()
            """,
            arn=arn,
        )
