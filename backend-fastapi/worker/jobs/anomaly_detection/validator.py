"""
Computes precision, recall, F1-score, accuracy, and false positive rate
by comparing flagged anomalies against ground truth (is_attack labels).
Produces the paper comparison table.
"""

from __future__ import annotations

CS_GAD_PAPER_RESULTS = {
    "lateral_movement": {"f1": 0.75, "fpr": 0.08, "recall": 0.85, "precision": 0.66},
    "targeted_service": {"f1": 0.71, "fpr": 0.10, "recall": 0.80, "precision": 0.64},
    "vulnerability_scan": {"f1": 0.78, "fpr": 0.05, "recall": 0.90, "precision": 0.69},
    "cryptojacking": {"f1": 0.82, "fpr": 0.04, "recall": 1.00, "precision": 0.70},
    "credential_theft": {"f1": 0.74, "fpr": 0.09, "recall": 0.85, "precision": 0.65},
}


def _safe_div(numerator: float, denominator: float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def compute_metrics(
    flagged: list[dict],
    all_principals_in_window: list[dict],
) -> dict:
    """
    Returns metrics comparing flagged principals to ground truth labels.
    """
    flagged_arns = {item["principal_arn"] for item in flagged}
    principals = {item["principal_arn"]: item for item in all_principals_in_window}

    tp = fp = tn = fn = 0
    for arn, meta in principals.items():
        is_attack = bool(meta.get("is_attack"))
        predicted = arn in flagged_arns
        if is_attack and predicted:
            tp += 1
        elif is_attack and not predicted:
            fn += 1
        elif not is_attack and predicted:
            fp += 1
        else:
            tn += 1

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1_score = _safe_div(2 * precision * recall, precision + recall)
    accuracy = _safe_div(tp + tn, tp + tn + fp + fn)
    false_positive_rate = _safe_div(fp, fp + tn)

    return {
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(false_positive_rate, 4),
    }


def compute_per_attack_metrics(all_results: list[dict]) -> dict[str, dict]:
    """
    Groups results by attack_type and computes metrics per type.
    Returns dict: attack_type → metrics dict
    """
    attack_types = {
        row.get("attack_type")
        for row in all_results
        if row.get("is_attack") and row.get("attack_type")
    }
    per_type: dict[str, dict] = {}

    for attack_type in sorted(attack_types):
        principals: list[dict] = []
        flagged: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for row in all_results:
            key = (row["principal_arn"], str(row.get("window_start", "")))
            if key in seen:
                continue
            seen.add(key)
            is_attack_row = bool(row.get("is_attack")) and row.get("attack_type") == attack_type
            is_normal = not row.get("is_attack")
            if not (is_attack_row or is_normal):
                continue
            principals.append(
                {
                    "principal_arn": row["principal_arn"],
                    "is_attack": is_attack_row,
                }
            )
            if row.get("flagged_as_anomaly"):
                flagged.append({"principal_arn": row["principal_arn"]})

        metrics = compute_metrics(flagged, principals)
        metrics["count"] = sum(1 for item in principals if item.get("is_attack"))
        per_type[attack_type] = metrics
    return per_type


def print_comparison_table(per_attack_metrics: dict[str, dict]) -> None:
    """
    Prints a formatted table:
    Attack Type | Paper F1 | Our NN F1 | Our Drift F1 | Paper FPR | Our FPR
    """
    header = f"{'Attack Type':<22} {'Paper F1':>10} {'Our F1':>10} {'Paper FPR':>10} {'Our FPR':>10}"
    print(header)
    print("-" * len(header))

    for attack_type, metrics in sorted(per_attack_metrics.items()):
        paper = CS_GAD_PAPER_RESULTS.get(
            attack_type,
            CS_GAD_PAPER_RESULTS.get("credential_theft", {"f1": 0.74, "fpr": 0.09}),
        )
        print(
            f"{attack_type:<22} "
            f"{paper['f1']:>10.2f} "
            f"{metrics.get('f1_score', 0.0):>10.2f} "
            f"{paper['fpr']:>10.2f} "
            f"{metrics.get('false_positive_rate', 0.0):>10.2f}"
        )

    if not per_attack_metrics:
        print("(no attack-type metrics available)")
