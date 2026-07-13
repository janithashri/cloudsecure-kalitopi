"""Unit tests for anomaly detection metrics helpers."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.anomaly_detection.pipeline import _metrics_summary


def test_metrics_summary_counts_principal_window_pairs() -> None:
    ws1 = datetime(2017, 5, 16, 23, tzinfo=timezone.utc)
    ws2 = datetime(2017, 5, 17, 23, tzinfo=timezone.utc)
    rows = [
        {"window_start": ws1, "principal_arn": "a", "is_attack": True, "flagged_as_anomaly": False},
        {"window_start": ws2, "principal_arn": "a", "is_attack": False, "flagged_as_anomaly": True},
        {"window_start": ws1, "principal_arn": "b", "is_attack": False, "flagged_as_anomaly": False},
    ]
    metrics = _metrics_summary(rows)
    assert metrics["true_positives"] + metrics["true_negatives"] + metrics["false_positives"] + metrics["false_negatives"] == 3
    assert metrics["false_positives"] == 1
    assert metrics["false_negatives"] == 1


if __name__ == "__main__":
    test_metrics_summary_counts_principal_window_pairs()
    print("ok")
