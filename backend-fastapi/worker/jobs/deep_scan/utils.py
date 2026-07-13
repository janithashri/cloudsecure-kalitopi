import os
import uuid
from contextlib import contextmanager

import neo4j
from cartography.config import Config as IngestionConfig

from app.core.config import get_settings
from app.models.orm import DeepScan

_driver_cache: dict[str, neo4j.Driver] = {}


def build_ingestion_config(deep_scan: DeepScan) -> IngestionConfig:
    settings = get_settings()
    update_tag = int(uuid.uuid4().int % (2**63 - 1))
    return IngestionConfig(
        neo4j_uri=settings.resolved_neo4j_shared_uri,
        neo4j_user=settings.resolved_neo4j_shared_user,
        neo4j_password=settings.resolved_neo4j_shared_password,
        neo4j_database=settings.neo4j_shared_database,
        update_tag=update_tag,
        permission_relationships_file=settings.cartography_permission_relationships_file,
        aws_best_effort_mode=True,
        aws_guardduty_severity_threshold=os.environ.get("AWS_GUARDDUTY_SEVERITY_THRESHOLD", "MEDIUM"),
        aws_cloudtrail_management_events_lookback_hours=int(
            os.environ.get("AWS_CLOUDTRAIL_LOOKBACK_HOURS", "24")
        ),
        experimental_aws_inspector_batch=os.environ.get("AWS_INSPECTOR_BATCH_EXPERIMENTAL", "false").lower()
        in ("1", "true", "yes"),
    )


def _get_or_create_driver(uri: str, auth: tuple[str, str]) -> neo4j.Driver:
    if uri not in _driver_cache:
        _driver_cache[uri] = neo4j.GraphDatabase.driver(uri, auth=auth)
    return _driver_cache[uri]


@contextmanager
def get_neo4j_session(ingestion_config: IngestionConfig):
    driver = _get_or_create_driver(
        ingestion_config.neo4j_uri,
        (ingestion_config.neo4j_user, ingestion_config.neo4j_password),
    )
    with driver.session(database=ingestion_config.neo4j_database) as session:
        yield session


@contextmanager
def get_tenant_neo4j_session(deep_scan: DeepScan):
    settings = get_settings()
    tenant_uri = _build_tenant_neo4j_uri(str(deep_scan.tenant_id))
    driver = _get_or_create_driver(
        tenant_uri,
        (
            settings.neo4j_tenant_user or settings.resolved_neo4j_shared_user,
            settings.neo4j_tenant_password or settings.resolved_neo4j_shared_password,
        ),
    )
    with driver.session(database=deep_scan.graph_database or "neo4j") as session:
        yield session


def _build_tenant_neo4j_uri(tenant_id: str) -> str:
    settings = get_settings()
    template = settings.neo4j_tenant_uri_template
    if template:
        return template.format(tenant_id=tenant_id)
    return settings.resolved_neo4j_shared_uri


def stringify_exception(exc: Exception, context: str = "") -> str:
    return f"{context}\nType: {type(exc).__name__}\nMessage: {str(exc)}"
