"""Score a few qualifying windows that contain attack principals."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.anomaly_detection.anomaly_scorer import (
    compute_threshold,
    drift_score,
    flag_anomalies,
    nn_distance_score,
)
from worker.jobs.anomaly_detection.flaws_loader import build_graphs_from_chunks
from worker.jobs.anomaly_detection.graph_builder import get_principal_nodes
from worker.jobs.anomaly_detection.node2vec_runner import get_principal_embeddings, run_node2vec


def main() -> None:
    chunk_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"D:\flaws_cloudtrail_logs")
    graphs, _, _ = build_graphs_from_chunks(chunk_dir, 10, window_hours=1)

    attack_windows = []
    for window_start, graph in graphs.items():
        principals = []
        for node in get_principal_nodes(graph):
            attrs = graph.nodes[node]
            principals.append(
                (
                    attrs.get("label") or node.removeprefix("P::"),
                    bool(attrs.get("is_attack")),
                    attrs.get("attack_type"),
                )
            )
        if len(principals) >= 3 and any(p[1] for p in principals):
            attack_windows.append((window_start, graph, principals))

    print(f"Found {len(attack_windows)} qualifying windows with attack principals")
    for window_start, graph, principals in attack_windows[:5]:
        embeddings = run_node2vec(graph, seed=42)
        principal_embeddings = get_principal_embeddings(embeddings, graph)
        nn_scores = nn_distance_score(principal_embeddings, graph)
        drift_scores = drift_score(principal_embeddings, {})
        combined = {
            arn: max(nn_scores.get(arn, 0.0), drift_scores.get(arn, 0.0))
            for arn in set(nn_scores) | set(drift_scores)
        }
        threshold = compute_threshold(combined)
        flagged = flag_anomalies(nn_scores, drift_scores, graph) if threshold != float("inf") else []
        flagged_arns = {f["principal_arn"] for f in flagged}

        print(f"\nWindow {window_start.isoformat()} ({len(principals)} principals)")
        print(f"  threshold={threshold:.4f}" if threshold != float("inf") else "  threshold=inf")
        for arn, is_attack, attack_type in sorted(principals, key=lambda x: (not x[1], x[0])):
            score = combined.get(arn, 0.0)
            mark = "FLAGGED" if arn in flagged_arns else "       "
            label = f"ATTACK:{attack_type}" if is_attack else "normal"
            print(f"  {mark} {label:30} nn={nn_scores.get(arn,0):.4f} drift={drift_scores.get(arn,0):.4f} final={score:.4f}")


if __name__ == "__main__":
    main()
