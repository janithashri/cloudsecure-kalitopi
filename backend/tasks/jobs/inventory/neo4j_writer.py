import json
import logging

from django.conf import settings
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

_driver = None


def get_neo4j_driver():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
        )
    return _driver


def write_resource_to_neo4j(driver, account_id: str, resource: dict):
    arn = resource["arn"]
    resource_type = resource["type"]
    config = resource["config"]

    with driver.session() as session:
        session.run(
            "MERGE (a:AWSAccount {account_id: $account_id})",
            account_id=account_id,
        )
        session.run(
            """
            MERGE (r:Resource {arn: $arn})
            SET r.type = $type,
                r.region = $region,
                r.config = $config,
                r.tags = $tags,
                r.last_seen = timestamp(),
                r.status = 'ACTIVE'
            """,
            arn=arn,
            type=resource_type,
            region=resource["region"],
            config=json.dumps(config),
            tags=json.dumps(resource.get("tags", {})),
        )
        session.run(
            """
            MATCH (a:AWSAccount {account_id: $account_id})
            MATCH (r:Resource {arn: $arn})
            MERGE (r)-[:BELONGS_TO]->(a)
            """,
            account_id=account_id,
            arn=arn,
        )
        _write_type_relationships(session, account_id, resource_type, arn, config)


def _write_type_relationships(session, account_id, resource_type, arn, config):
    if resource_type == "AWS::EC2::Instance":
        if config.get("vpc_id"):
            session.run(
                """
                MERGE (v:AWSVPC {vpc_id: $vpc_id, account_id: $account_id})
                WITH v
                MATCH (r:Resource {arn: $arn})
                MERGE (r)-[:MEMBER_OF_VPC]->(v)
                """,
                vpc_id=config["vpc_id"],
                account_id=account_id,
                arn=arn,
            )
        for sg_id in config.get("security_groups", []):
            session.run(
                """
                MERGE (sg:AWSSecurityGroup {group_id: $sg_id, account_id: $account_id})
                WITH sg
                MATCH (r:Resource {arn: $arn})
                MERGE (r)-[:USES_SECURITY_GROUP]->(sg)
                """,
                sg_id=sg_id,
                account_id=account_id,
                arn=arn,
            )
    elif resource_type == "AWS::RDS::DBInstance":
        for sg_id in config.get("vpc_security_groups", []):
            session.run(
                """
                MERGE (sg:AWSSecurityGroup {group_id: $sg_id, account_id: $account_id})
                WITH sg
                MATCH (r:Resource {arn: $arn})
                MERGE (r)-[:USES_SECURITY_GROUP]->(sg)
                """,
                sg_id=sg_id,
                account_id=account_id,
                arn=arn,
            )
    elif resource_type == "AWS::EC2::SecurityGroup":
        sg_id = config.get("group_id")
        if sg_id:
            session.run(
                """
                MERGE (sg:AWSSecurityGroup {group_id: $sg_id, account_id: $account_id})
                """,
                sg_id=sg_id,
                account_id=account_id,
            )


def tombstone_resource(driver, arn: str):
    with driver.session() as session:
        session.run(
            """
            MATCH (r:Resource {arn: $arn})
            SET r.status = 'DELETED',
                r.deleted_at = timestamp()
            """,
            arn=arn,
        )
    logger.info("Tombstoned resource: %s", arn)
