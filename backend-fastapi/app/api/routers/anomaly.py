from datetime import datetime

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sklearn.decomposition import PCA
from sqlalchemy.orm import Session

from app.api.deps import get_current_tenant
from app.core.database import get_db
from app.models.anomaly_orm import AnomalyRun
from app.models.orm import Tenant
from app.schemas.anomaly import (
    AnomalyFindingOut,
    AnomalyMetricsOut,
    AnomalyRunDetail,
    AnomalyRunQueuedResponse,
    AnomalyRunRequest,
    AnomalyRunSummary,
    EmbeddingPoint,
    EmbeddingsOut,
)
from worker.jobs.anomaly_detection.storage import (
    create_anomaly_run,
    get_findings,
    get_recent_runs,
    get_run_for_tenant,
)
from worker.jobs.anomaly_detection.validator import CS_GAD_PAPER_RESULTS

router = APIRouter(prefix="/api/v1/anomaly", tags=["anomaly"])


def _run_summary(run: AnomalyRun) -> AnomalyRunSummary:
    return AnomalyRunSummary(
        id=run.id,
        dataset_path=run.dataset_path,
        status=run.status,
        window_hours=run.window_hours,
        total_windows=run.total_windows,
        total_principals=run.total_principals,
        total_flagged=run.total_flagged,
        overall_f1=run.overall_f1,
        overall_precision=run.overall_precision,
        overall_recall=run.overall_recall,
        overall_fpr=run.overall_fpr,
        created_at=run.created_at,
        completed_at=run.completed_at,
    )


@router.post("/run/", response_model=AnomalyRunQueuedResponse, status_code=status.HTTP_202_ACCEPTED)
def start_anomaly_run(
    body: AnomalyRunRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    run = create_anomaly_run(
        db,
        tenant_id=tenant.id,
        dataset_path=body.dataset_path,
        window_hours=body.window_hours,
        provider_id=body.provider_id,
    )

    from worker.jobs.anomaly_detection.task import run_anomaly_detection_task

    run_anomaly_detection_task.apply_async(
        kwargs={
            "run_id": run.id,
            "tenant_id": tenant.id,
            "dataset_path": body.dataset_path,
            "window_hours": body.window_hours,
        },
        queue="anomaly",
    )
    return AnomalyRunQueuedResponse(run_id=run.id, status="queued")


@router.get("/runs/", response_model=list[AnomalyRunSummary])
def list_anomaly_runs(
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    runs = get_recent_runs(db, tenant.id, limit=10)
    return [_run_summary(run) for run in runs]


@router.get("/runs/{run_id}/", response_model=AnomalyRunDetail)
def get_anomaly_run(
    run_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    run = get_run_for_tenant(db, run_id, tenant.id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return AnomalyRunDetail(**_run_summary(run).model_dump(), stats=run.stats or {})


@router.get("/runs/{run_id}/findings/", response_model=list[AnomalyFindingOut])
def list_anomaly_findings(
    run_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
    window_start: datetime | None = None,
    min_score: float | None = Query(default=None),
    attack_type: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
):
    run = get_run_for_tenant(db, run_id, tenant.id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    findings = get_findings(
        db,
        run_id,
        window_start=window_start,
        min_score=min_score,
        attack_type=attack_type,
        offset=offset,
        limit=limit,
    )
    return [
        AnomalyFindingOut(
            id=f.id,
            window_start=f.window_start,
            principal_arn=f.principal_arn,
            final_score=f.final_score,
            nn_score=f.nn_score,
            drift_score=f.drift_score,
            threshold=f.threshold,
            is_true_positive=f.is_true_positive,
            attack_type=f.attack_type,
            graph_stats=f.graph_stats or {},
            created_at=f.created_at,
        )
        for f in findings
    ]


@router.get("/runs/{run_id}/metrics/", response_model=AnomalyMetricsOut)
def get_anomaly_metrics(
    run_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    run = get_run_for_tenant(db, run_id, tenant.id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    stats = run.stats or {}
    per_attack = stats.get("per_attack_metrics", {})
    overall = {
        "precision": run.overall_precision,
        "recall": run.overall_recall,
        "f1_score": run.overall_f1,
        "false_positive_rate": run.overall_fpr,
    }

    paper_comparison = []
    for attack_type, metrics in per_attack.items():
        paper = CS_GAD_PAPER_RESULTS.get(attack_type, {"f1": 0.74, "fpr": 0.09})
        paper_comparison.append(
            {
                "attack_type": attack_type,
                "paper_f1": paper["f1"],
                "our_f1": metrics.get("f1_score"),
                "paper_fpr": paper["fpr"],
                "our_fpr": metrics.get("false_positive_rate"),
            }
        )

    return AnomalyMetricsOut(
        overall=overall,
        per_attack_type=per_attack,
        paper_comparison=paper_comparison,
    )


@router.get("/runs/{run_id}/embeddings/{window}/", response_model=EmbeddingsOut)
def get_window_embeddings(
    run_id: int,
    window: str,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
    reduced: bool = Query(default=False),
):
    run = get_run_for_tenant(db, run_id, tenant.id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    embeddings_raw = (run.stats or {}).get("embeddings", {}).get(window)
    if embeddings_raw is None:
        embeddings_raw = (run.stats or {}).get("embeddings_export", {}).get(window, {})

    if not embeddings_raw:
        raise HTTPException(status_code=404, detail="Embeddings not found for window")

    arns = list(embeddings_raw.keys())
    matrix = np.stack([np.array(embeddings_raw[arn], dtype=np.float32) for arn in arns])

    if reduced:
        if matrix.shape[0] >= 2:
            coords = PCA(n_components=2, random_state=42).fit_transform(matrix)
        else:
            coords = np.zeros((len(arns), 2), dtype=np.float32)
    else:
        coords = matrix[:, :2] if matrix.shape[1] >= 2 else np.zeros((len(arns), 2))

    labels = {
        row.get("principal_arn"): bool(row.get("is_attack"))
        for row in (run.stats or {}).get("anomaly_labels", [])
    }
    attack_types = {
        row.get("principal_arn"): row.get("attack_type")
        for row in (run.stats or {}).get("anomaly_labels", [])
    }

    points = [
        EmbeddingPoint(
            principal_arn=arn,
            x=float(coords[idx, 0]),
            y=float(coords[idx, 1]),
            is_attack=labels.get(arn, False),
            attack_type=attack_types.get(arn),
        )
        for idx, arn in enumerate(arns)
    ]
    return EmbeddingsOut(window=window, points=points, reduced=reduced)
