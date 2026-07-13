import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_tenant, get_user_profile
from app.core.database import get_db
from app.db import repositories as repo
from app.db.repositories import utcnow
from app.models.orm import InventoryRun, Provider, Tenant
from app.schemas.providers import (
    InventoryPullResponse,
    InventoryRunOut,
    ProviderCreate,
    ProviderOut,
    ProviderUpdate,
)
from worker.tasks import disable_inventory_pull, perform_inventory_pull_task, schedule_inventory_pull

router = APIRouter(prefix="/api/v1", tags=["providers"])


def _get_provider(db: Session, tenant: Tenant, pk: int) -> Provider:
    provider = repo.get_provider_for_tenant(db, pk, tenant.id)
    if not provider:
        raise HTTPException(status_code=404, detail="Not found")#404 prevents idor 
    return provider


@router.get("/providers/", response_model=list[ProviderOut])
def list_providers(tenant: Tenant = Depends(get_current_tenant), db: Session = Depends(get_db)):
    return list(db.scalars(select(Provider).where(Provider.tenant_id == tenant.id)))


@router.post("/providers/", response_model=ProviderOut, status_code=status.HTTP_201_CREATED)
def create_provider(
    body: ProviderCreate,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    now = utcnow()
    provider = Provider(
        tenant_id=tenant.id,
        name=body.name,
        aws_account_id=body.aws_account_id,
        inventory_role_name=body.inventory_role_name,
        active=body.active,
        connection_verified=False,
        created_at=now,
        updated_at=now,
    )
    db.add(provider)
    db.commit()
    db.refresh(provider)# reload obj from db pk fetched to orm object
    return provider


@router.patch("/providers/{pk}/", response_model=ProviderOut)
def update_provider(
    pk: int,
    body: ProviderUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    provider = _get_provider(db, tenant, pk)
    for field, value in body.model_dump(exclude_unset=True).items():# patch behaviour to prevent overwrite & ignores some schema field
        setattr(provider, field, value)#dirty track auto update in orm identity map
    provider.updated_at = utcnow()
    db.commit()
    db.refresh(provider)
    return provider


@router.delete("/providers/{pk}/", status_code=status.HTTP_204_NO_CONTENT)
def delete_provider(pk: int, tenant: Tenant = Depends(get_current_tenant), db: Session = Depends(get_db)):
    provider = _get_provider(db, tenant, pk)
    disable_inventory_pull(provider.id)
    db.delete(provider)
    db.commit()


@router.post("/providers/{pk}/test-connection/")
def test_connection(pk: int, tenant: Tenant = Depends(get_current_tenant), db: Session = Depends(get_db)):
    provider = _get_provider(db, tenant, pk)
    role_arn = f"arn:aws:iam::{provider.aws_account_id}:role/{provider.inventory_role_name}"
    try:
        sts = boto3.client("sts")
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="CloudSecureConnectionTest",
            DurationSeconds=900,
        )
        provider.connection_verified = True
        provider.last_connection_test = utcnow()
        provider.updated_at = utcnow()
        db.commit()
        schedule_inventory_pull(provider.id, tenant.id)
        return {
            "status": "success",
            "account_id": provider.aws_account_id,
            "assumed_role_arn": assumed["AssumedRoleUser"]["Arn"],
        }
    except ClientError as e:#aws error
        provider.connection_verified = False
        provider.updated_at = utcnow()
        db.commit()
        msg = e.response.get("Error", {}).get("Message", str(e))
        raise HTTPException(status_code=400, detail={"status": "error", "message": msg})
    except Exception as e:#non aws error crashes/unexpected/unknown error 
        provider.connection_verified = False
        provider.updated_at = utcnow()
        db.commit()
        raise HTTPException(status_code=400, detail={"status": "error", "message": str(e)})


@router.get("/providers/{pk}/inventory-runs/", response_model=list[InventoryRunOut])
def list_inventory_runs(pk: int, tenant: Tenant = Depends(get_current_tenant), db: Session = Depends(get_db)):
    _get_provider(db, tenant, pk)
    runs = db.scalars(
        select(InventoryRun)
        .where(InventoryRun.provider_id == pk)
        .order_by(InventoryRun.started_at.desc())
        .limit(10)
    )
    out = []
    for run in runs:
        stats = run.stats or {}
        if "config_changed_signals" not in stats:
            stats = {**stats, "config_changed_signals": 0}#** unpacks dict to another
        out.append(
            InventoryRunOut(
                id=run.id,
                state=run.state,
                started_at=run.started_at,
                completed_at=run.completed_at,
                stats=stats,
            )
        )
    return out


@router.post("/providers/{pk}/inventory-pull/", response_model=InventoryPullResponse, status_code=202)
def inventory_pull(pk: int, tenant: Tenant = Depends(get_current_tenant), db: Session = Depends(get_db)):
    _get_provider(db, tenant, pk)
    if repo.has_running_inventory_run(db, pk):
        raise HTTPException(status_code=409, detail="Inventory pull already in progress")
    task = perform_inventory_pull_task.delay(tenant.id, pk)
    return InventoryPullResponse(task_id=task.id, status="queued")

