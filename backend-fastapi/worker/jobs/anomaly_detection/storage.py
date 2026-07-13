"""Save/load anomaly detection results to PostgreSQL."""

from __future__ import annotations

from datetime import datetime, timezone

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.anomaly_orm import AnomalyFinding, AnomalyRun, PrincipalEmbedding


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def create_anomaly_run(
    db: Session,
    *,
    tenant_id: int,
    dataset_path: str,
    window_hours: int = 1,
    provider_id: int | None = None,
) -> AnomalyRun:
    run = AnomalyRun(
        tenant_id=tenant_id,
        provider_id=provider_id,
        dataset_path=dataset_path,
        status="running",
        window_hours=window_hours,
        created_at=utcnow(),
        stats={},
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def finalize_anomaly_run(db: Session, run_id: int, results: dict, status: str = "completed") -> AnomalyRun | None:
    run = db.get(AnomalyRun, run_id)
    if not run:
        return None

    overall = results.get("overall_metrics", {})
    run.status = status
    run.total_windows = results.get("total_windows", 0)
    run.total_flagged = results.get("total_flagged", 0)
    run.total_principals = results.get("total_principals", 0)
    run.overall_f1 = overall.get("f1_score")
    run.overall_precision = overall.get("precision")
    run.overall_recall = overall.get("recall")
    run.overall_fpr = overall.get("false_positive_rate")
    run.stats = {
        "category_distribution": results.get("category_distribution", {}),
        "per_attack_metrics": results.get("per_attack_metrics", {}),
        "window_metrics": results.get("window_metrics", {}),
        "unknown_category_pct": results.get("unknown_category_pct"),
        "total_events": results.get("total_events"),
        "embeddings": results.get("embeddings", {}),
        "anomaly_labels": results.get("principal_labels", []),
    }
    run.completed_at = utcnow()
    db.commit()
    db.refresh(run)
    return run


def save_findings(db: Session, run: AnomalyRun, anomalies: list[dict]) -> int:
    count = 0
    for item in anomalies:
        window_start = item.get("window_start")
        if isinstance(window_start, str):
            window_start = datetime.fromisoformat(window_start.replace("Z", "+00:00"))

        finding = AnomalyFinding(
            run_id=run.id,
            tenant_id=run.tenant_id,
            window_start=window_start,
            principal_arn=item["principal_arn"],
            final_score=item["final_score"],
            nn_score=item["nn_score"],
            drift_score=item["drift_score"],
            threshold=item["threshold"],
            is_true_positive=item.get("is_attack") if item.get("is_attack") is not None else None,
            attack_type=item.get("attack_type"),
            graph_stats={},
            created_at=utcnow(),
        )
        db.add(finding)
        count += 1
    db.commit()
    return count


def save_embeddings(
    db: Session,
    embeddings_by_window: dict[str, dict[str, list[float]]],
    account_id: str = "unknown",
) -> int:
    count = 0
    for window_label, embeddings in embeddings_by_window.items():
        window_start = datetime.fromisoformat(window_label.replace("Z", "+00:00"))
        for principal_arn, vector in embeddings.items():
            existing = db.scalar(
                select(PrincipalEmbedding).where(
                    PrincipalEmbedding.principal_arn == principal_arn,
                    PrincipalEmbedding.window_start == window_start,
                )
            )
            if existing:
                existing.embedding = vector
                existing.account_id = account_id
            else:
                db.add(
                    PrincipalEmbedding(
                        principal_arn=principal_arn,
                        window_start=window_start,
                        embedding=vector,
                        account_id=account_id,
                        created_at=utcnow(),
                    )
                )
            count += 1
    db.commit()
    return count


def load_historical_embeddings(
    db: Session,
    principal_arn: str,
    max_windows: int = 14 * 24,
) -> list[np.ndarray]:
    rows = db.scalars(
        select(PrincipalEmbedding)
        .where(PrincipalEmbedding.principal_arn == principal_arn)
        .order_by(PrincipalEmbedding.window_start.desc())
        .limit(max_windows)
    ).all()
    return [np.array(row.embedding, dtype=np.float32) for row in reversed(rows)]


def load_all_historical_embeddings(db: Session, max_windows: int = 14 * 24) -> dict[str, list[np.ndarray]]:
    rows = db.scalars(
        select(PrincipalEmbedding).order_by(PrincipalEmbedding.window_start.asc())
    ).all()
    history: dict[str, list[np.ndarray]] = {}
    for row in rows:
        history.setdefault(row.principal_arn, []).append(np.array(row.embedding, dtype=np.float32))
    for arn in history:
        if len(history[arn]) > max_windows:
            history[arn] = history[arn][-max_windows:]
    return history


def get_recent_runs(db: Session, tenant_id: int, limit: int = 10) -> list[AnomalyRun]:
    return list(
        db.scalars(
            select(AnomalyRun)
            .where(AnomalyRun.tenant_id == tenant_id)
            .order_by(AnomalyRun.created_at.desc())
            .limit(limit)
        ).all()
    )


def get_run_for_tenant(db: Session, run_id: int, tenant_id: int) -> AnomalyRun | None:
    return db.scalar(
        select(AnomalyRun).where(AnomalyRun.id == run_id, AnomalyRun.tenant_id == tenant_id)
    )


def get_findings(
    db: Session,
    run_id: int,
    *,
    window_start: datetime | None = None,
    min_score: float | None = None,
    attack_type: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> list[AnomalyFinding]:
    query = select(AnomalyFinding).where(AnomalyFinding.run_id == run_id)
    if window_start is not None:
        query = query.where(AnomalyFinding.window_start == window_start)
    if min_score is not None:
        query = query.where(AnomalyFinding.final_score >= min_score)
    if attack_type is not None:
        query = query.where(AnomalyFinding.attack_type == attack_type)
    query = query.order_by(AnomalyFinding.final_score.desc()).offset(offset).limit(limit)
    return list(db.scalars(query).all())
