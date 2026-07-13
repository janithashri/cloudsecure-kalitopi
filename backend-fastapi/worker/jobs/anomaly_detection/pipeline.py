"""
Orchestrates the full anomaly detection pipeline end to end.
Entry point: run_anomaly_pipeline(dataset_dir, output_dir)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from worker.jobs.anomaly_detection.action_categoriser import categorise_events, get_category_distribution
from worker.jobs.anomaly_detection.anomaly_scorer import (
    compute_threshold,
    drift_score,
    flag_anomalies,
    nn_distance_score,
    update_historical_embeddings,
)
from worker.jobs.anomaly_detection.cloudtrail_parser import get_time_windows, parse_directory
from worker.jobs.anomaly_detection.graph_builder import build_all_windows, get_graph_stats, get_principal_nodes
from worker.jobs.anomaly_detection.node2vec_runner import get_principal_embeddings, run_all_windows
from worker.jobs.anomaly_detection.embedding_stability import check_embedding_stability
from worker.jobs.anomaly_detection.validator import compute_metrics, compute_per_attack_metrics, print_comparison_table

CS_GAD_PAPER_POOLED = {"precision": 0.66, "recall": 0.85, "f1_score": 0.75, "false_positive_rate": 0.08}
STRATUS_INVICTUS_POOLED = {"precision": 0.50, "recall": 0.25, "f1_score": 0.33, "false_positive_rate": 0.33}

logger = logging.getLogger(__name__)


def _window_principal_count(graph) -> int:
    return len(list(get_principal_nodes(graph)))


def _dataset_stats(events, windowed_graphs, category_distribution) -> dict:
    principals_per_window = [_window_principal_count(g) for g in windowed_graphs.values()]
    total_windows = len(windowed_graphs)
    ge3 = sum(1 for n in principals_per_window if n >= 3)
    return {
        "total_events": len(events),
        "total_windows": total_windows,
        "avg_principals_per_window": round(sum(principals_per_window) / total_windows, 2) if total_windows else 0.0,
        "min_principals_per_window": min(principals_per_window) if principals_per_window else 0,
        "max_principals_per_window": max(principals_per_window) if principals_per_window else 0,
        "windows_with_ge_3_principals": ge3,
        "pct_windows_with_ge_3_principals": round(100.0 * ge3 / total_windows, 2) if total_windows else 0.0,
        "category_distribution": category_distribution,
    }


def _metrics_summary(rows: list[dict]) -> dict:
    """Micro-average metrics over principal-window pairs (no cross-window dedup)."""
    flagged = [{"principal_arn": _row_key(row)} for row in rows if row.get("flagged_as_anomaly")]
    principals = [{"principal_arn": _row_key(row), "is_attack": row["is_attack"]} for row in rows]
    return compute_metrics(flagged, principals)


def _row_key(row: dict) -> str:
    window_start = row["window_start"]
    window_label = window_start.isoformat() if hasattr(window_start, "isoformat") else str(window_start)
    return f"{row['principal_arn']}::{window_label}"


def _is_qualifying_window(graph, min_principals: int = 3) -> bool:
    return _window_principal_count(graph) >= min_principals


def _macro_metrics(window_metrics: dict[str, dict], window_keys: list[str]) -> dict:
    """Macro-average per-window metrics across qualifying windows."""
    keys = [key for key in window_keys if key in window_metrics and not window_metrics[key].get("insufficient_data")]
    if not keys:
        return {}
    totals = {
        "precision": 0.0,
        "recall": 0.0,
        "f1_score": 0.0,
        "false_positive_rate": 0.0,
        "accuracy": 0.0,
    }
    for key in keys:
        metrics = window_metrics[key]
        for field in totals:
            totals[field] += float(metrics.get(field, 0.0))
    count = len(keys)
    return {field: round(value / count, 4) for field, value in totals.items()}


def _principal_labels(graph) -> list[dict]:
    principals = []
    for node_id in get_principal_nodes(graph):
        attrs = graph.nodes[node_id]
        principals.append(
            {
                "principal_arn": attrs.get("label") or node_id.removeprefix("P::"),
                "is_attack": bool(attrs.get("is_attack")),
                "attack_type": attrs.get("attack_type"),
            }
        )
    return principals


def _serialise_for_json(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _serialise_for_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_serialise_for_json(v) for v in value]
    return value


def _flatten_windowed_events(windowed_events) -> list[dict]:
    events: list[dict] = []
    for batch in windowed_events.values():
        events.extend(batch)
    return events


def _run_scoring_pipeline(
    *,
    dataset_label: str,
    output_path: Path,
    events: list[dict],
    category_distribution: dict,
    window_hours: int,
    windowed_graphs,
    historical_embeddings: dict | None = None,
    min_qualifying_windows: int = 300,
    chunk_meta: dict | None = None,
) -> dict:
    """Score pre-built window graphs and write pooled results."""
    total_events = len(events)
    unknown_pct = 100.0 * category_distribution.get("Unknown", 0) / total_events if total_events else 0.0
    dataset_stats = _dataset_stats(events, windowed_graphs, category_distribution)
    embedding_stability = check_embedding_stability(windowed_graphs)
    window_embeddings = run_all_windows(windowed_graphs)

    history = historical_embeddings or {}
    all_flagged: list[dict] = []
    all_window_results: list[dict] = []
    window_metrics: dict[str, dict] = {}
    embeddings_export: dict[str, dict] = {}

    insufficient_windows: list[str] = []
    qualifying_window_keys: list[str] = []
    attack_principal_slots = 0
    attack_windows = 0

    for window_start, graph in windowed_graphs.items():
        embeddings = window_embeddings.get(window_start, {})
        principal_embeddings = get_principal_embeddings(embeddings, graph)

        principals = _principal_labels(graph)
        qualifying = _is_qualifying_window(graph)
        if not qualifying:
            history = update_historical_embeddings(history, principal_embeddings)
            continue

        qualifying_window_keys.append(window_start.isoformat())
        if any(p["is_attack"] for p in principals):
            attack_windows += 1
            attack_principal_slots += sum(1 for p in principals if p["is_attack"])

        nn_scores = nn_distance_score(principal_embeddings, graph)
        drift_scores = drift_score(principal_embeddings, history)
        combined_scores = {
            arn: max(nn_scores.get(arn, 0.0), drift_scores.get(arn, 0.0))
            for arn in set(nn_scores) | set(drift_scores)
        }
        threshold = compute_threshold(combined_scores)
        insufficient_data = threshold == float("inf")
        if insufficient_data:
            logger.warning(
                "Qualifying window %s has insufficient scores for threshold (principal_count=%s, score_count=%s)",
                window_start.isoformat(),
                len(principals),
                len(combined_scores),
            )
            insufficient_windows.append(window_start.isoformat())
            flagged = []
        else:
            flagged = flag_anomalies(nn_scores, drift_scores, graph)

        for item in flagged:
            item["window_start"] = window_start

        for principal in principals:
            arn = principal["principal_arn"]
            all_window_results.append(
                {
                    "window_start": window_start,
                    "principal_arn": arn,
                    "is_attack": principal["is_attack"],
                    "attack_type": principal["attack_type"],
                    "nn_score": nn_scores.get(arn, 0.0),
                    "drift_score": drift_scores.get(arn, 0.0),
                    "final_score": max(nn_scores.get(arn, 0.0), drift_scores.get(arn, 0.0)),
                    "flagged_as_anomaly": arn in {f["principal_arn"] for f in flagged},
                }
            )

        metrics = compute_metrics(flagged, principals)
        window_metrics[window_start.isoformat()] = {
            **metrics,
            "threshold": None if insufficient_data else threshold,
            "insufficient_data": insufficient_data,
            "flagged_count": len(flagged),
            "principal_count": len(principals),
            "attack_principal_count": sum(1 for p in principals if p["is_attack"]),
        }
        all_flagged.extend(flagged)
        history = update_historical_embeddings(history, principal_embeddings)

        if len(windowed_graphs) <= 250:
            embeddings_export[window_start.isoformat()] = {
                arn: vector.tolist() for arn, vector in principal_embeddings.items()
            }

    scorable_window_keys = [
        key for key in qualifying_window_keys if key not in insufficient_windows
    ]
    scorable_rows = [row for row in all_window_results if row["window_start"].isoformat() in scorable_window_keys]
    pooled_scorable_metrics = _metrics_summary(scorable_rows)
    macro_pooled_metrics = _macro_metrics(window_metrics, scorable_window_keys)
    per_window_f1_values = [
        window_metrics[key]["f1_score"]
        for key in scorable_window_keys
        if key in window_metrics and not window_metrics[key].get("insufficient_data")
    ]
    distinct_qualifying_principals = len({row["principal_arn"] for row in scorable_rows})
    metrics_ready = (
        len(scorable_window_keys) >= min_qualifying_windows
        and embedding_stability.get("passed", False)
    )

    overall_flagged = [item for item in all_flagged if item["window_start"].isoformat() in scorable_window_keys]
    overall_principals = [
        {"principal_arn": row["principal_arn"], "is_attack": row["is_attack"]}
        for row in scorable_rows
    ]
    overall_metrics = pooled_scorable_metrics if metrics_ready else {}
    per_attack_metrics = compute_per_attack_metrics(scorable_rows) if metrics_ready else {}

    if metrics_ready:
        print_comparison_table(per_attack_metrics)
    else:
        logger.warning(
            "Metrics withheld: %s qualifying windows (need %s), "
            "embedding stability %.1f%% (need 80%%).",
            len(scorable_window_keys),
            min_qualifying_windows,
            embedding_stability.get("stable_flagged_status_pct", 0.0),
        )

    total_principals = len({row["principal_arn"] for row in all_window_results})
    principal_labels = {}
    for event in events:
        arn = event["principal_arn"]
        if arn not in principal_labels:
            principal_labels[arn] = {
                "principal_arn": arn,
                "is_attack": event["is_attack"],
                "attack_type": event.get("attack_type"),
            }
        elif event["is_attack"]:
            principal_labels[arn]["is_attack"] = True
            if event.get("attack_type"):
                principal_labels[arn]["attack_type"] = event.get("attack_type")

    comparison_notes = {
        "cs_gad_paper_pooled": CS_GAD_PAPER_POOLED,
        "stratus_invictus_pooled": STRATUS_INVICTUS_POOLED,
        "explanation": (
            "Stratus/invictus-ir used ~2 windows with 6-12 principals; adaptive threshold "
            "inflated F1 to ~0.33. flaws.cloud uses the paper's unmodified mu+2sigma threshold "
            "and service-level NN peer groups. Pooled micro metrics count every principal-window "
            "pair in qualifying windows; macro metrics average per-window F1. Attack events are "
            "sparse in multi-principal windows (~1% of qualifying slots), so peer-based anomaly "
            "detection often misses colluding attackers."
        ),
    }

    results = {
        "dataset_dir": dataset_label,
        "window_hours": window_hours,
        "total_events": total_events,
        "attack_events": sum(1 for e in events if e["is_attack"]),
        "normal_events": sum(1 for e in events if not e["is_attack"]),
        "category_distribution": category_distribution,
        "unknown_category_pct": round(unknown_pct, 2),
        "dataset_stats": dataset_stats,
        "embedding_stability": embedding_stability,
        "metrics_ready": metrics_ready,
        "total_windows": len(windowed_graphs),
        "scorable_windows": len(scorable_window_keys),
        "qualifying_windows": len(qualifying_window_keys),
        "qualifying_windows_with_attacks": attack_windows,
        "attack_principal_slots_in_qualifying": attack_principal_slots,
        "principal_slots_in_qualifying": len(scorable_rows),
        "distinct_principals_in_qualifying_windows": distinct_qualifying_principals,
        "min_qualifying_windows": min_qualifying_windows,
        "insufficient_windows": insufficient_windows,
        "total_principals": total_principals,
        "total_flagged": len(overall_flagged),
        "pooled_scorable_metrics": pooled_scorable_metrics,
        "macro_pooled_metrics": macro_pooled_metrics,
        "per_window_f1_range": {
            "min": min(per_window_f1_values) if per_window_f1_values else None,
            "max": max(per_window_f1_values) if per_window_f1_values else None,
            "values": per_window_f1_values,
        },
        "overall_metrics": overall_metrics,
        "per_attack_metrics": per_attack_metrics,
        "window_metrics": window_metrics,
        "comparison_notes": comparison_notes,
        "anomalies": [_serialise_for_json(item) for item in overall_flagged],
        "principal_labels": list(principal_labels.values()),
        "embeddings": embeddings_export,
        "graph_stats_sample": {
            key.isoformat(): get_graph_stats(graph)
            for key, graph in list(windowed_graphs.items())[:3]
        },
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    if chunk_meta:
        results["chunk_meta"] = chunk_meta
        results["qualifying_window_stats"] = {
            "qualifying_windows": len(scorable_window_keys),
            "distinct_principals_in_qualifying": distinct_qualifying_principals,
            **{
                k: chunk_meta.get(k)
                for k in ("n_chunks", "pct_qualifying", "avg_principals_per_window")
                if k in chunk_meta
            },
        }

    results_file = output_path / "anomaly_results.json"
    if len(windowed_graphs) > 250:
        compact = {k: v for k, v in results.items() if k not in ("embeddings", "window_metrics", "anomalies")}
        compact["window_metrics_sample"] = dict(list(window_metrics.items())[:20])
        compact["anomalies_count"] = len(overall_flagged)
        with open(results_file, "w", encoding="utf-8") as handle:
            json.dump(_serialise_for_json(compact), handle, indent=2)
    else:
        with open(results_file, "w", encoding="utf-8") as handle:
            json.dump(_serialise_for_json(results), handle, indent=2)

    logger.info("Saved anomaly results to %s", results_file)
    return results


def run_anomaly_pipeline(
    dataset_dir: str,
    output_dir: str,
    window_hours: int = 1,
    historical_embeddings: dict | None = None,
    min_qualifying_windows: int = 300,
) -> dict:
    """
    Full pipeline from a directory of CloudTrail JSON files.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    dataset_path = Path(dataset_dir)
    if not dataset_path.is_dir():
        raise FileNotFoundError(
            f"Dataset directory not found: {dataset_dir}. "
            "In Docker, use /data/aws_dataset and set ANOMALY_DATASET_HOST_PATH in .env."
        )

    events = categorise_events(parse_directory(str(dataset_path)))
    if not events:
        json_files = list(dataset_path.rglob("*.json")) + list(dataset_path.rglob("*.json.gz"))
        raise ValueError(
            f"No CloudTrail events parsed from {dataset_dir} "
            f"({len(json_files)} JSON files found). Check mount path and file format."
        )
    category_distribution = get_category_distribution(events)
    windowed_events = get_time_windows(events, window_hours=window_hours)
    windowed_graphs = build_all_windows(windowed_events, min_events_per_window=5)

    return _run_scoring_pipeline(
        dataset_label=dataset_dir,
        output_path=output_path,
        events=events,
        category_distribution=category_distribution,
        window_hours=window_hours,
        windowed_graphs=windowed_graphs,
        historical_embeddings=historical_embeddings,
        min_qualifying_windows=min_qualifying_windows,
    )


def run_anomaly_pipeline_from_chunks(
    chunk_dir: str,
    n_chunks: int,
    output_dir: str,
    window_hours: int = 1,
    historical_embeddings: dict | None = None,
    min_qualifying_windows: int = 300,
) -> dict:
    """
    Incrementally merge flaws.cloud gzip chunks, build hourly graphs, score pooled qualifying windows.
    """
    from worker.jobs.anomaly_detection.flaws_loader import (
        merge_chunks_incrementally,
        qualifying_window_stats,
    )

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    chunk_path = Path(chunk_dir)
    windowed_events, meta = merge_chunks_incrementally(chunk_path, n_chunks, window_hours=window_hours)
    windowed_graphs = build_all_windows(windowed_events, min_events_per_window=5)
    qual_stats = qualifying_window_stats(windowed_graphs)
    events = _flatten_windowed_events(windowed_events)

    logger.info(
        "Chunks 0-%s: %s events, %s total windows, %s qualifying (>=3 principals), "
        "%s distinct principals in qualifying windows",
        n_chunks - 1,
        meta["total_events"],
        meta["total_windows"],
        qual_stats["qualifying_windows"],
        qual_stats["distinct_principals_in_qualifying"],
    )

    if qual_stats["qualifying_windows"] < min_qualifying_windows:
        raise ValueError(
            f"Only {qual_stats['qualifying_windows']} qualifying windows "
            f"(need {min_qualifying_windows}). Scale to 15-20 chunks before reporting."
        )

    chunk_meta = {**meta, **qual_stats}

    return _run_scoring_pipeline(
        dataset_label=f"{chunk_dir} [chunks 0-{n_chunks - 1}]",
        output_path=output_path,
        events=events,
        category_distribution=meta["category_distribution"],
        window_hours=window_hours,
        windowed_graphs=windowed_graphs,
        historical_embeddings=historical_embeddings,
        min_qualifying_windows=min_qualifying_windows,
        chunk_meta=chunk_meta,
    )


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if len(sys.argv) > 1 and sys.argv[1] == "--chunks":
        chunk_dir = sys.argv[2] if len(sys.argv) > 2 else r"D:\flaws_cloudtrail_logs"
        n_chunks = int(sys.argv[3]) if len(sys.argv) > 3 else 10
        output = (
            sys.argv[4]
            if len(sys.argv) > 4
            else r"C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\output\anomaly\flaws_chunks0_9"
        )
        run_anomaly_pipeline_from_chunks(chunk_dir, n_chunks, output)
    else:
        dataset = (
            sys.argv[1]
            if len(sys.argv) > 1
            else r"C:\Users\Admin\Downloads\aws_dataset-main\aws_dataset-main"
        )
        output = (
            sys.argv[2]
            if len(sys.argv) > 2
            else r"C:\Users\Admin\cloud-secure\kaali-topi\cloudsecure\output\anomaly"
        )
        run_anomaly_pipeline(dataset, output)
