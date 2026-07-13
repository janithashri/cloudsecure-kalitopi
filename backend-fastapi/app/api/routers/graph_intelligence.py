from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_tenant
from app.core.database import get_db
from app.db import repositories as repo
from app.models.orm import DeepScan, Provider, Tenant
from app.services.graph_intelligence_service import get_graph_intelligence

router = APIRouter(prefix="/api/v1", tags=["graph-intelligence"])


def _provider(db: Session, tenant: Tenant, provider_id: int) -> Provider:
    provider = repo.get_provider_for_tenant(db, provider_id, tenant.id)
    if not provider:
        raise HTTPException(status_code=404, detail="Not found")
    return provider


@router.get("/providers/{provider_id}/graph-intelligence/")
def graph_intelligence_get(
    provider_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    provider = _provider(db, tenant, provider_id)
    return get_graph_intelligence(db, provider)


@router.post("/providers/{provider_id}/graph-intelligence/run/", status_code=status.HTTP_202_ACCEPTED)
def graph_intelligence_run(
    provider_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    provider = _provider(db, tenant, provider_id)
    last_scan = db.scalar(
        select(DeepScan)
        .where(
            DeepScan.provider_id == provider.id,
            DeepScan.tenant_id == tenant.id,
            DeepScan.state == "COMPLETED",
        )
        .order_by(DeepScan.completed_at.desc())
        .limit(1)
    )
    if last_scan is None:
        raise HTTPException(status_code=400, detail="No completed Deep Scan found for provider")

    from worker.jobs.deep_scan.graph_analytics_task import run_graph_analytics_task

    task = run_graph_analytics_task.apply_async(#apply_async overrides the config
        kwargs={
            "provider_id": provider.id,
            "deep_scan_id": str(last_scan.scan_id),
            "tenant_id": tenant.id,
        },
        queue="deep_scan",
    )
    return {"status": "started", "task_id": task.id}
