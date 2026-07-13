from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_tenant
from app.core.database import get_db
from app.db import repositories as repo
from app.models.orm import DeepScan, Provider, Tenant
router = APIRouter(prefix="/api/v1", tags=["deep-scan"])


def _celery_app():
    from worker.celery_app import celery_app

    return celery_app


class DeepScanCreate(BaseModel):
    provider_id: int


@router.post("/deep-scan/", status_code=status.HTTP_201_CREATED)
def create_deep_scan(
    body: DeepScanCreate,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    provider = repo.get_provider_for_tenant(db, body.provider_id, tenant.id)
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    scan = repo.create_deep_scan(db, tenant.id, provider.id)
    task = _celery_app().send_task(
        "worker.jobs.deep_scan.scan.run",
        kwargs={
            "tenant_id": str(tenant.id),
            "scan_id": str(scan.scan_id),
            "provider_id": provider.id,
        },
        queue="deep_scan",
    )
    scan.task_id = task.id
    db.commit()
    return {"scan_id": str(scan.scan_id), "state": scan.state}


@router.get("/deep-scan/")
def list_deep_scans(
    provider_id: int,
    limit: int = 20,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    scans = db.scalars(
        select(DeepScan)
        .where(DeepScan.provider_id == provider_id, DeepScan.tenant_id == tenant.id)
        .order_by(DeepScan.started_at.desc())
        .limit(limit)
    )
    scans_list = []
    for scan in scans:
        scans_list.append(
            {
                "scan_id": str(scan.scan_id),
                "state": scan.state,
                "progress": scan.progress,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration": scan.duration,
                "update_tag": scan.update_tag,
                "ingestion_exceptions": scan.ingestion_exceptions or {},
            }
        )
    return {"scans": scans_list}


@router.get("/deep-scan/{scan_id}/")
def get_deep_scan(
    scan_id: UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    scan = repo.get_deep_scan(db, str(scan_id), tenant.id)
    if not scan:
        raise HTTPException(status_code=404, detail="Not found")
    return {
        "scan_id": str(scan.scan_id),
        "state": scan.state,
        "progress": scan.progress,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "duration": scan.duration,
        "update_tag": scan.update_tag,
        "graph_database": scan.graph_database,
        "ingestion_exceptions": scan.ingestion_exceptions or {},
        "is_graph_db_deleted": scan.is_graph_database_deleted,
    }


@router.delete("/deep-scan/{scan_id}/")
def cancel_deep_scan(
    scan_id: UUID,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    scan = repo.get_deep_scan(db, str(scan_id), tenant.id)
    if not scan:
        raise HTTPException(status_code=404, detail="Not found")
    if scan.state in ("COMPLETED", "FAILED"):
        raise HTTPException(status_code=409, detail="Scan is already in a terminal state")
    if scan.task_id:
        _celery_app().control.revoke(scan.task_id, terminate=True, signal="SIGTERM")
    scan.state = "FAILED"
    scan.ingestion_exceptions = {"global_error": "Cancelled by user"}
    db.commit()
    return {"cancelled": True}
