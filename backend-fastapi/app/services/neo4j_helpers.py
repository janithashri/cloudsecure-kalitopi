"""Neo4j helpers for the API layer (no Cartography dependency)."""

from app.core.config import get_settings


def build_tenant_neo4j_uri(tenant_id: str) -> str:
    settings = get_settings()
    template = settings.neo4j_tenant_uri_template
    if template:
        return template.format(tenant_id=tenant_id)
    return settings.resolved_neo4j_shared_uri
