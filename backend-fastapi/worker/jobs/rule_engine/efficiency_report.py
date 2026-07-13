"""
Standalone script computing precision/recall/F1/reduction metrics for
Features 3 and 4, written to a separate report file — not mixed into
application code paths. Run manually or via a management command after
a scan against test buckets/keys with known ground truth.
"""
import json
import os
from datetime import datetime, timezone

from sqlalchemy import or_, select

from app.core.database import SessionLocal
from app.models.orm import Finding


def compute_efficiency_report(provider_id: int, ground_truth: dict) -> dict:
    """
    ground_truth: {arn_or_key_id: "true_positive" | "false_positive"}
    Manually annotated by testing against your known test resources
    (mirrors Paper A/B's manual TP/FP classification methodology).
    """
    with SessionLocal() as db:
        old_findings = db.scalars(
            select(Finding).where(
                Finding.provider_id == provider_id,
                or_(
                    Finding.rule_id.like("CIS-2.1%"),
                    Finding.rule_id.like("DPDP-S3%"),
                ),
            )
        ).all()
        new_findings = db.scalars(
            select(Finding).where(
                Finding.provider_id == provider_id,
                Finding.rule_id == "CONSOLIDATED-S3-001",
            )
        ).all()
        validated_open = [f for f in new_findings if f.status == "OPEN"]

    def confusion(findings_list, label):
        tp = fp = 0
        for f in findings_list:
            truth = ground_truth.get(f.arn)
            if truth == "true_positive":
                tp += 1
            elif truth == "false_positive":
                fp += 1
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        return {
            "stage": label,
            "total_alerts": len(findings_list),
            "tp": tp,
            "fp": fp,
            "precision": round(precision, 3),
        }

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "provider_id": provider_id,
        "stage_baseline_old_rules": confusion(old_findings, "old_fragmented_rules"),
        "stage_consolidated_rule": confusion(new_findings, "consolidated_rule"),
        "stage_actively_validated": confusion(validated_open, "actively_validated"),
    }

    base_precision = report["stage_baseline_old_rules"]["precision"]
    validated_precision = report["stage_actively_validated"]["precision"]
    report["overall_precision_improvement_pct"] = (
        round(((validated_precision - base_precision) / base_precision) * 100, 1)
        if base_precision
        else None
    )
    report["overall_alert_reduction_pct"] = (
        round(
            (1 - report["stage_actively_validated"]["total_alerts"] / report["stage_baseline_old_rules"]["total_alerts"])
            * 100,
            1,
        )
        if report["stage_baseline_old_rules"]["total_alerts"]
        else 0
    )

    os.makedirs("reports", exist_ok=True)
    output_path = f"reports/efficiency_report_provider_{provider_id}.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return report
