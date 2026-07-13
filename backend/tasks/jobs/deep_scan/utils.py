import os
import time
import uuid
from contextlib import contextmanager

import neo4j
from cartography.config import Config as IngestionConfig

from api.models import DeepScan as DeepScanModel

_driver_cache: dict[str, neo4j.Driver] = {}


def build_ingestion_config(deep_scan: DeepScanModel) -> IngestionConfig:
    from django.conf import settings

    # Must be unique per scan to avoid cross-tenant/provider snapshot collisions
    # when multiple deep scans run simultaneously.
    update_tag = int(uuid.uuid4().int % (2**63 - 1))
    perm_file = getattr(settings, "CARTOGRAPHY_PERMISSION_RELATIONSHIPS_FILE", "")
    return IngestionConfig(
        neo4j_uri=settings.NEO4J_SHARED_URI,
        neo4j_user=settings.NEO4J_SHARED_USER,
        neo4j_password=settings.NEO4J_SHARED_PASSWORD,
        neo4j_database=getattr(settings, "NEO4J_SHARED_DATABASE", "neo4j"),
        update_tag=update_tag,
        permission_relationships_file=perm_file,
        aws_best_effort_mode=True,
        aws_guardduty_severity_threshold=getattr(settings, "AWS_GUARDDUTY_SEVERITY_THRESHOLD", "MEDIUM"),
        aws_cloudtrail_management_events_lookback_hours=getattr(settings, "AWS_CLOUDTRAIL_LOOKBACK_HOURS", 24),
        experimental_aws_inspector_batch=getattr(settings, "AWS_INSPECTOR_BATCH_EXPERIMENTAL", False),
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
def get_tenant_neo4j_session(deep_scan: DeepScanModel):
    from django.conf import settings

    tenant_uri = _build_tenant_neo4j_uri(deep_scan.tenant_id)
    driver = _get_or_create_driver(
        tenant_uri,
        (
            getattr(settings, "NEO4J_TENANT_USER", settings.NEO4J_SHARED_USER),
            getattr(settings, "NEO4J_TENANT_PASSWORD", settings.NEO4J_SHARED_PASSWORD),
        ),
    )
    with driver.session(database=deep_scan.graph_database or "neo4j") as session:
        yield session


def _build_tenant_neo4j_uri(tenant_id: str) -> str:
    from django.conf import settings

    template = getattr(settings, "NEO4J_TENANT_URI_TEMPLATE", "")
    if template:
        return template.format(tenant_id=tenant_id)
    return settings.NEO4J_SHARED_URI


def stringify_exception(exc: Exception, context: str = "") -> str:
    return f"{context}\nType: {type(exc).__name__}\nMessage: {str(exc)}"
