import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class AuthUser(Base):
    __tablename__ = "auth_user"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    password: Mapped[str] = mapped_column(String(128))
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    username: Mapped[str] = mapped_column(String(150), unique=True)
    first_name: Mapped[str] = mapped_column(String(150), default="")
    last_name: Mapped[str] = mapped_column(String(150), default="")
    email: Mapped[str] = mapped_column(String(254), default="")
    is_staff: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    date_joined: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    profile: Mapped["UserProfile"] = relationship(back_populates="user", uselist=False)
    token: Mapped["AuthToken | None"] = relationship(back_populates="user", uselist=False)


class AuthToken(Base):
    __tablename__ = "authtoken_token"

    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("auth_user.id", ondelete="CASCADE"), unique=True)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    user: Mapped[AuthUser] = relationship(back_populates="token")


class Tenant(Base):
    __tablename__ = "accounts_tenant"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class UserProfile(Base):
    __tablename__ = "accounts_userprofile"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("auth_user.id", ondelete="CASCADE"), unique=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("accounts_tenant.id", ondelete="CASCADE"))

    user: Mapped[AuthUser] = relationship(back_populates="profile")
    tenant: Mapped[Tenant] = relationship()


class Provider(Base):
    __tablename__ = "providers_provider"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("accounts_tenant.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255))
    aws_account_id: Mapped[str] = mapped_column(String(12))
    inventory_role_name: Mapped[str] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    connection_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    last_connection_test: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class InventoryRun(Base):
    __tablename__ = "api_inventoryrun"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("accounts_tenant.id", ondelete="CASCADE"))
    provider_id: Mapped[int] = mapped_column(ForeignKey("providers_provider.id", ondelete="CASCADE"))
    state: Mapped[str] = mapped_column(String(20), default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stats: Mapped[dict] = mapped_column(JSONB, default=dict)


class ResourceStateHash(Base):
    __tablename__ = "api_resourcestatehash"
    __table_args__ = (UniqueConstraint("account_id", "arn"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[str] = mapped_column(String(64))
    arn: Mapped[str] = mapped_column(Text)
    tag_hash: Mapped[str] = mapped_column(String(64))
    config_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ResourceConfig(Base):
    __tablename__ = "api_resourceconfig"
    __table_args__ = (UniqueConstraint("account_id", "arn"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[str] = mapped_column(String(64))
    arn: Mapped[str] = mapped_column(Text)
    resource_type: Mapped[str] = mapped_column(String(128))
    region: Mapped[str] = mapped_column(String(64))
    config: Mapped[dict] = mapped_column(JSONB)
    tags: Mapped[dict] = mapped_column(JSONB, default=dict)
    last_updated: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    __tablename__ = "api_finding"
    __table_args__ = (UniqueConstraint("arn", "rule_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("accounts_tenant.id", ondelete="CASCADE"))
    provider_id: Mapped[int] = mapped_column(ForeignKey("providers_provider.id", ondelete="CASCADE"))
    inventory_run_id: Mapped[int] = mapped_column(ForeignKey("api_inventoryrun.id", ondelete="CASCADE"))
    arn: Mapped[str] = mapped_column(Text)
    account_id: Mapped[str] = mapped_column(String(64))
    resource_type: Mapped[str] = mapped_column(String(128))
    region: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(128))
    rule_name: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(48), default="OPEN")
    compliance_frameworks: Mapped[list] = mapped_column(JSONB, default=list)
    remediation_steps: Mapped[str] = mapped_column(Text, default="")
    raw_finding: Mapped[dict] = mapped_column(JSONB, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CustomRule(Base):
    __tablename__ = "api_customrule"
    __table_args__ = (UniqueConstraint("tenant_id", "rule_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("accounts_tenant.id", ondelete="CASCADE"))
    provider_id: Mapped[int | None] = mapped_column(
        ForeignKey("providers_provider.id", ondelete="CASCADE"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(150))
    resource_type: Mapped[str] = mapped_column(String(128))
    rule_id: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM")
    compliance_frameworks: Mapped[list] = mapped_column(JSONB, default=list)
    description: Mapped[str] = mapped_column(Text, default="")
    rego_policy: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("auth_user.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ConfigChangeCursor(Base):
    __tablename__ = "api_configchangecursor"
    __table_args__ = (UniqueConstraint("account_id", "region"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[str] = mapped_column(String(64))
    region: Mapped[str] = mapped_column(String(32), default="ap-south-1")
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class DeepScan(Base):
    __tablename__ = "deep_scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), unique=True, default=uuid.uuid4)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("accounts_tenant.id", ondelete="CASCADE"))
    provider_id: Mapped[int] = mapped_column(ForeignKey("providers_provider.id", ondelete="CASCADE"))
    state: Mapped[str] = mapped_column(String(20), default="SCHEDULED")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration: Mapped[int | None] = mapped_column(Integer, nullable=True)
    task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    update_tag: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    graph_database: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_graph_database_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    ingestion_exceptions: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=dict)
