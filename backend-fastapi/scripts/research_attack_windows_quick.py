"""Quick research method comparison on windows that contain attacks (~16 windows)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.research_graph_eval import METHODS, _pool, _score_window
from worker.jobs.anomaly_detection.flaws_loader import build_graphs_from_chunks
from worker.jobs.anomaly_detection.graph_builder import get_principal_nodes
from worker.jobs.anomaly_detection.node2vec_runner import get_principal_embeddings, run_node2vec
from worker.jobs.anomaly_detection.anomaly_scorer import update_historical_embeddings


def main() -> None:
    graphs, _, _ = build_graphs_from_chunks(Path(r"D:\flaws_cloudtrail_logs"), 10, 1)
    method_rows = {m: [] for m in METHODS}
    history = {}

    for window_start, graph in sorted(graphs.items(), key=lambda x: x[0]):
        pe = get_principal_embeddings(run_node2vec(graph, seed=42), graph)
        history = update_historical_embeddings(history, pe)

        principals = [
            (graph.nodes[n].get("label") or n.removeprefix("P::"), bool(graph.nodes[n].get("is_attack")))
            for n in get_principal_nodes(graph)
        ]
        if len(principals) < 3 or not any(a for _, a in principals):
            continue
        for method in METHODS:
            _, flagged = _score_window(method, graph, pe, history)
            flagged_arns = {f["principal_arn"] for f in flagged}
            for arn, is_attack in principals:
                method_rows[method].append(
                    {
                        "window_start": window_start,
                        "principal_arn": arn,
                        "is_attack": is_attack,
                        "flagged_as_anomaly": arn in flagged_arns,
                    }
                )

    print("Attack-window subset (qualifying windows with ground-truth attacks):\n")
    for method in METHODS:
        m = _pool(method_rows[method])
        print(f"{method}: P={m['precision']} R={m['recall']} F1={m['f1_score']} TP={m['true_positives']} FP={m['false_positives']} FN={m['false_negatives']}")


if __name__ == "__main__":
    main()
