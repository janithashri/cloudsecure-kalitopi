from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.orm import (
    AuthToken,
    AuthUser,
    ConfigChangeCursor,
    CustomRule,
    DeepScan,
    Finding,
    InventoryRun,
    Provider,
    ResourceConfig,
    ResourceStateHash,
    Tenant,
    UserProfile,
)

#identity map ensures one copy of orm object of same query in a session
#flush updates and sends transaction but others cant see commit does flush+commit add only tracks 
#flush makes the transaction commit makes it permanent and vis for other transactions- transaction isolation using mvcc xmin xmax
#identity map chanegs with every update but expires if rollback before commit, refresh is used to fetch default or indexed key into orm obj id map
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --- Inventory runs ---


def create_inventory_run(db: Session, tenant_id: int, provider_id: int) -> InventoryRun:
    run = InventoryRun(
        tenant_id=tenant_id,
        provider_id=provider_id,
        state="running",
        started_at=utcnow(),
        stats={},
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def finalize_inventory_run(db: Session, run_id: int, state: str, stats: dict) -> None:
    db.execute(
        update(InventoryRun)
        .where(InventoryRun.id == run_id)
        .values(state=state, stats=stats, completed_at=utcnow())
    )
    db.commit()


def has_running_inventory_run(db: Session, provider_id: int) -> bool:
    row = db.scalar(
        select(InventoryRun.id)
        .where(InventoryRun.provider_id == provider_id, InventoryRun.state == "running")
        .limit(1)
    )
    return row is not None


def get_latest_inventory_run(db: Session, provider_id: int) -> InventoryRun | None:
    return db.scalar(
        select(InventoryRun)
        .where(InventoryRun.provider_id == provider_id)
        .order_by(InventoryRun.started_at.desc())
        .limit(1)
    )


# --- Providers / tenants ---


def get_provider(db: Session, provider_id: int) -> Provider | None:
    return db.get(Provider, provider_id)


def get_provider_for_tenant(db: Session, provider_id: int, tenant_id: int) -> Provider | None:
    return db.scalar(
        select(Provider).where(Provider.id == provider_id, Provider.tenant_id == tenant_id)
    )


def get_tenant(db: Session, tenant_id: int) -> Tenant | None:
    return db.get(Tenant, tenant_id)


# --- Resource state hashes ---


def load_hashes(db: Session, account_id: str) -> dict[str, dict]:
    rows = db.scalars(select(ResourceStateHash).where(ResourceStateHash.account_id == account_id))
    return {
        row.arn: {"tag_hash": row.tag_hash, "config_hash": row.config_hash}
        for row in rows
    }


def save_hashes(db: Session, account_id: str, hashes: dict[str, dict]) -> None:
    for arn, hash_data in hashes.items():
        stmt = insert(ResourceStateHash).values(
            account_id=account_id,
            arn=arn,
            tag_hash=hash_data["tag_hash"],
            config_hash=hash_data.get("config_hash"),
            updated_at=utcnow(),
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["account_id", "arn"],
            set_={
                "tag_hash": stmt.excluded.tag_hash,
                "config_hash": stmt.excluded.config_hash,
                "updated_at": utcnow(),
            },
        )
        db.execute(stmt)
    if hashes:
        db.execute(
            delete(ResourceStateHash).where(
                ResourceStateHash.account_id == account_id,
                ResourceStateHash.arn.not_in(list(hashes.keys())),
            )
        )
    else:
        db.execute(delete(ResourceStateHash).where(ResourceStateHash.account_id == account_id))
    db.commit()


# --- Resource config ---


def upsert_resource_config(
    db: Session,
    account_id: str,
    arn: str,
    resource_type: str,
    region: str,
    config: dict,
    tags: dict,
) -> None:
    stmt = insert(ResourceConfig).values(
        account_id=account_id,
        arn=arn,
        resource_type=resource_type,
        region=region,
        config=config,
        tags=tags,
        last_updated=utcnow(),
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["account_id", "arn"],
        set_={
            "resource_type": stmt.excluded.resource_type,
            "region": stmt.excluded.region,
            "config": stmt.excluded.config,
            "tags": stmt.excluded.tags,
            "last_updated": utcnow(),
        },
    )
    db.execute(stmt)
    db.commit()


def mark_resource_config_deleted(db: Session, account_id: str, arn: str) -> None:
    db.execute(
        update(ResourceConfig)
        .where(ResourceConfig.account_id == account_id, ResourceConfig.arn == arn)
        .values(config={"_deleted": True, "_deleted_at": str(utcnow())})
    )
    db.commit()


def list_resource_configs_for_account(db: Session, account_id: str) -> list[ResourceConfig]:
    rows = db.scalars(select(ResourceConfig).where(ResourceConfig.account_id == account_id))
    return [r for r in rows if not (isinstance(r.config, dict) and r.config.get("_deleted"))]


def get_resource_config(db: Session, account_id: str, arn: str) -> ResourceConfig | None:
    return db.scalar(
        select(ResourceConfig).where(
            ResourceConfig.account_id == account_id, ResourceConfig.arn == arn
        )
    )


# --- Findings ---


def finding_exists(db: Session, arn: str, rule_id: str) -> Finding | None:
    return db.scalar(
        select(Finding).where(Finding.arn == arn, Finding.rule_id == rule_id)
    )


def create_finding(db: Session, **kwargs: Any) -> Finding:
    finding = Finding(**kwargs)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def update_finding(db: Session, finding: Finding, **kwargs: Any) -> None:
    for k, v in kwargs.items():
        setattr(finding, k, v)
    db.commit()


def finding_exists_for_arn_tenant(db: Session, arn: str, tenant_id: int) -> bool:
    return (
        db.scalar(
            select(Finding.id).where(Finding.arn == arn, Finding.tenant_id == tenant_id).limit(1)
        )
        is not None
    )


def get_enabled_custom_rules(
    db: Session, tenant_id: int, resource_type: str, provider_id: int | None = None
) -> list[CustomRule]:
    q = select(CustomRule).where(
        CustomRule.tenant_id == tenant_id,
        CustomRule.enabled.is_(True),
        CustomRule.resource_type == resource_type,
    )
    if provider_id is not None:
        q = q.where((CustomRule.provider_id == provider_id) | (CustomRule.provider_id.is_(None)))
    return list(db.scalars(q))


# --- Config drift cursor ---


def get_or_create_config_cursor(db: Session, account_id: str, region: str) -> ConfigChangeCursor:
    row = db.scalar(
        select(ConfigChangeCursor).where(
            ConfigChangeCursor.account_id == account_id,
            ConfigChangeCursor.region == region,
        )
    )
    if row:
        return row
    row = ConfigChangeCursor(account_id=account_id, region=region, updated_at=utcnow())
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def update_config_cursor(db: Session, cursor: ConfigChangeCursor, last_polled_at: datetime) -> None:
    cursor.last_polled_at = last_polled_at
    cursor.updated_at = utcnow()
    db.commit()


# --- Deep scan ---


def create_deep_scan(db: Session, tenant_id: int, provider_id: int) -> DeepScan:
    scan = DeepScan(tenant_id=tenant_id, provider_id=provider_id, state="SCHEDULED")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_deep_scan(db: Session, scan_id: str, tenant_id: int) -> DeepScan | None:
    return db.scalar(
        select(DeepScan).where(DeepScan.scan_id == scan_id, DeepScan.tenant_id == tenant_id)
    )


def get_provider_for_deep_scan(db: Session, provider_id: int, tenant_id: int) -> Provider | None:
    return get_provider_for_tenant(db, provider_id, tenant_id)


def update_deep_scan(db: Session, scan: DeepScan, **kwargs: Any) -> None:
    for k, v in kwargs.items():
        setattr(scan, k, v)
    db.commit()


def retrieve_deep_scan(db: Session, tenant_id: str, scan_id: str) -> DeepScan | None:
    return db.scalar(
        select(DeepScan).where(
            DeepScan.tenant_id == int(tenant_id),
            DeepScan.scan_id == scan_id,
        )
    )


# --- Auth ---


def get_user_by_username(db: Session, username: str) -> AuthUser | None:
    return db.scalar(select(AuthUser).where(AuthUser.username == username))


def get_user_by_username_or_email(db: Session, login: str) -> AuthUser | None:
    """Match Django-style login: username or email in one field."""
    value = login.strip()
    if not value:
        return None
    user = get_user_by_username(db, value)
    if user is not None:
        return user
    return db.scalar(select(AuthUser).where(AuthUser.email == value))


def get_user_by_token(db: Session, token_key: str) -> AuthUser | None:
    return db.scalar(
        select(AuthUser)
        .join(AuthToken, AuthToken.user_id == AuthUser.id)
        .where(AuthToken.key == token_key, AuthUser.is_active.is_(True))
    )


def get_or_create_token(db: Session, user_id: int, key: str | None = None) -> AuthToken:
    from app.core.security import generate_token_key

    existing = db.scalar(select(AuthToken).where(AuthToken.user_id == user_id))
    if existing:
        return existing
    token = AuthToken(key=key or generate_token_key(), user_id=user_id, created=utcnow())
    db.add(token)
    db.commit()
    db.refresh(token)
    return token


def delete_user_token(db: Session, user_id: int) -> None:
    db.execute(delete(AuthToken).where(AuthToken.user_id == user_id))
    db.commit()


def get_user_profile(db: Session, user_id: int) -> UserProfile | None:
    return db.scalar(select(UserProfile).where(UserProfile.user_id == user_id))


def create_user_with_tenant(
    db: Session, username: str, email: str, password_hash: str, tenant_name: str
) -> AuthUser:
    user = AuthUser(
        username=username,
        email=email or username,
        password=password_hash,
        is_superuser=False,
        is_staff=False,
        is_active=True,
        first_name="",
        last_name="",
        date_joined=utcnow(),
    )
    db.add(user)
    db.flush()
    tenant = Tenant(name=tenant_name, created_at=utcnow())
    db.add(tenant)
    db.flush()
    db.add(UserProfile(user_id=user.id, tenant_id=tenant.id))
    db.commit()
    db.refresh(user)
    return user
