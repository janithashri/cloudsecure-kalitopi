"""
Checks Node2Vec embedding stability across random seeds before reporting metrics.
"""

from __future__ import annotations

from datetime import datetime

import networkx as nx

from worker.jobs.anomaly_detection.anomaly_scorer import (
    compute_threshold,
    drift_score,
    flag_anomalies,
    nn_distance_score,
)
from worker.jobs.anomaly_detection.node2vec_runner import get_principal_embeddings, run_node2vec


def _flagged_arns_for_seed(
    graph: nx.DiGraph,
    history: dict,
    seed: int,
) -> tuple[set[str], dict[str, float]]:
    embeddings = run_node2vec(graph, seed=seed)
    principal_embeddings = get_principal_embeddings(embeddings, graph)
    nn_scores = nn_distance_score(principal_embeddings, graph)
    drift_scores = drift_score(principal_embeddings, history)
    combined = {
        arn: max(nn_scores.get(arn, 0.0), drift_scores.get(arn, 0.0))
        for arn in set(nn_scores) | set(drift_scores)
    }
    threshold = compute_threshold(combined)
    if threshold == float("inf"):
        return set(), combined
    flagged = flag_anomalies(nn_scores, drift_scores, graph)
    return {item["principal_arn"] for item in flagged}, combined


def check_embedding_stability(
    windowed_graphs: dict[datetime, nx.DiGraph],
    seeds: list[int] | None = None,
    min_test_windows: int = 3,
    min_principals: int = 3,
) -> dict:
    """
    Re-run Node2Vec on selected windows with multiple seeds.
    Returns stability report including consistency percentage.
    """
    seeds = seeds or [42, 123, 999]
    eligible = [
        (window_start, graph)
        for window_start, graph in windowed_graphs.items()
        if len([n for n, attrs in graph.nodes(data=True) if attrs.get("node_type") == "principal"]) >= min_principals
    ]
    test_windows = eligible[: min(min_test_windows, len(eligible))]

    window_reports: list[dict] = []
    stable_principals = 0
    tested_principals = 0

    for window_start, graph in test_windows:
        principal_arns = [
            attrs.get("label") or node.removeprefix("P::")
            for node, attrs in graph.nodes(data=True)
            if attrs.get("node_type") == "principal"
        ]
        per_seed_flags: dict[int, set[str]] = {}
        per_seed_ranks: dict[int, dict[str, int]] = {}

        for seed in seeds:
            flagged, combined = _flagged_arns_for_seed(graph, {}, seed)
            per_seed_flags[seed] = flagged
            ranked = sorted(combined.items(), key=lambda item: item[1], reverse=True)
            per_seed_ranks[seed] = {arn: idx for idx, (arn, _) in enumerate(ranked)}

        window_stable = 0
        for arn in principal_arns:
            tested_principals += 1
            flags = [arn in per_seed_flags[seed] for seed in seeds]
            if len(set(flags)) == 1:
                stable_principals += 1
                window_stable += 1

        window_reports.append(
            {
                "window_start": window_start.isoformat(),
                "principal_count": len(principal_arns),
                "stable_flagged_status_count": window_stable,
                "stable_flagged_status_pct": round(100.0 * window_stable / len(principal_arns), 2)
                if principal_arns
                else 0.0,
                "seeds": seeds,
            }
        )

    consistency_pct = round(100.0 * stable_principals / tested_principals, 2) if tested_principals else 0.0
    passed = consistency_pct >= 80.0 and len(test_windows) >= min(min_test_windows, len(eligible))

    return {
        "seeds": seeds,
        "windows_tested": len(test_windows),
        "windows_eligible": len(eligible),
        "principals_tested": tested_principals,
        "stable_flagged_status_count": stable_principals,
        "stable_flagged_status_pct": consistency_pct,
        "passed": passed,
        "window_reports": window_reports,
    }
