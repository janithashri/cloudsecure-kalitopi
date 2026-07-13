"""Celery task for graph-based anomaly detection."""

from __future__ import annotations

import logging
import traceback

from worker.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="worker.jobs.anomaly_detection.task.run_anomaly_detection", bind=True)
def run_anomaly_detection_task(
    self,
    run_id: int,
    tenant_id: int,
    dataset_path: str,
    window_hours: int = 1,
    output_dir: str | None = None,
):
    from app.core.database import SessionLocal
    from worker.jobs.anomaly_detection.pipeline import run_anomaly_pipeline
    from worker.jobs.anomaly_detection.storage import (
        finalize_anomaly_run,
        load_all_historical_embeddings,
        save_embeddings,
        save_findings,
    )

    db = SessionLocal()
    try:
        historical = load_all_historical_embeddings(db)
        out_dir = output_dir or f"/tmp/anomaly_run_{run_id}"
        results = run_anomaly_pipeline(
            dataset_path,
            out_dir,
            window_hours=window_hours,
            historical_embeddings=historical,
        )
        run = finalize_anomaly_run(db, run_id, results, status="completed")
        if run:
            save_findings(db, run, results.get("anomalies", []))
            save_embeddings(db, results.get("embeddings", {}))
        return {"run_id": run_id, "status": "completed", "total_flagged": results.get("total_flagged", 0)}
    except Exception as exc:
        logger.exception("Anomaly detection failed for run %s", run_id)
        from app.models.anomaly_orm import AnomalyRun

        run = db.get(AnomalyRun, run_id)
        if run:
            run.status = "failed"
            run.stats = {"error": str(exc), "traceback": traceback.format_exc()}
            db.commit()
        raise
    finally:
        db.close()
