import os
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote_plus

from pydantic_settings import BaseSettings, SettingsConfigDict

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_ENV_FILE = _PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE) if _ENV_FILE.exists() else None,
        extra="ignore",
    )

    secret_key: str = "dev-only-change-me"
    debug: bool = True

    postgres_db: str = "cloudsecure"
    postgres_user: str = "cloudsecure"
    postgres_password: str = ""
    postgres_host: str = "db"
    postgres_port: str = "5432"

    valkey_url: str = "redis://valkey:6379/0"

    neo4j_uri: str = ""
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""

    neo4j_shared_uri: str = ""
    neo4j_shared_user: str = ""
    neo4j_shared_password: str = ""
    neo4j_shared_database: str = "neo4j"
    neo4j_tenant_uri_template: str = ""
    neo4j_tenant_user: str = ""
    neo4j_tenant_password: str = ""

    opa_url: str = "http://opa:8181"
    rules_dir: str = ""

    aws_default_region: str = "us-east-1"
    enable_aws_config_drift: bool = False
    aws_config_region: str = ""
    aws_config_initial_lookback_minutes: int = 180
    enable_s3_fallback_discovery: bool = False
    consolidated_s3_rules_enabled: bool = True
    # When False (demo default), legacy fragmented public S3 rules are stored alongside CONSOLIDATED-S3-001.
    suppress_fragmented_s3_public_rules: bool = False

    cartography_permission_relationships_file: str = ""

    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    @property
    def cors_origin_regex(self) -> str | None:
        """In dev, allow LAN / Docker host origins (any port) for the Vite dev server."""
        if not self.debug:
            return None
        return (
            r"https?://("
            r"localhost|127\.0\.0\.1|host\.docker\.internal|"
            r"(?:\d{1,3}\.){3}\d{1,3}"
            r")(:\d+)?$"
        )

    @property
    def database_url(self) -> str:
        # Passwords with @, :, /, etc. must be URL-encoded or psycopg gets the wrong host.
        user = quote_plus(self.postgres_user)
        password = quote_plus(self.postgres_password)
        return (
            f"postgresql+psycopg://{user}:{password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def resolved_neo4j_shared_uri(self) -> str:
        return self.neo4j_shared_uri or self.neo4j_uri

    @property
    def resolved_neo4j_shared_user(self) -> str:
        return self.neo4j_shared_user or self.neo4j_user
    #they are functions that behave like attributes but can have logic and side effects
    @property
    def resolved_neo4j_shared_password(self) -> str:
        return self.neo4j_shared_password or self.neo4j_password
    #properties can compute validate cache while appearing like normal var field enforcing encapsualtion adn flexibility to change in future+ redability
    @property
    def resolved_rules_dir(self) -> str:
        if self.rules_dir:
            return self.rules_dir
        return str(Path(__file__).resolve().parents[2] / "worker" / "jobs" / "inventory" / "rules")

#for lazy initialization as it is singleton use lru cache it uses dict liek storage 
###Dependency Injection (DI) is a design technique where a component does not create or manage its own dependencies. Instead, dependencies are provided externally by the framework or another system. In FastAPI, this reduces tight coupling between routes and services, allows dependency replacement/testing, and lets FastAPI build and resolve a dependency graph before executing route logic.
#now fastapi manages creation injection lifecycle and cleanup 
@lru_cache
def get_settings() -> Settings:
    return Settings()
