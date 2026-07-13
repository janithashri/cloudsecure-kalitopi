"""
Research evaluation: compare graph-only detection methods (no IP rules).

Methods (all use Node2Vec embeddings + mu+2sigma threshold):
  cs_gad_peer     - CS-GAD paper: NN distance to any same-service peer
  org_peer_nn     - NN distance to legitimate org baseline peers only
  org_centroid    - Distance to centroid of legitimate embeddings
  combined_org    - max(peer_nn, drift, org_peer_nn, org_centroid)
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.anomaly_detection.anomaly_scorer import (
    combine_scores,
    drift_score,
    flag_anomalies_from_combined,
    nn_distance_score,
    organizational_centroid_score,
    organizational_peer_nn_score,
    update_historical_embeddings,
)
from worker.jobs.anomaly_detection.flaws_loader import build_graphs_from_chunks
from worker.jobs.anomaly_detection.graph_builder import get_principal_nodes
from worker.jobs.anomaly_detection.node2vec_runner import get_principal_embeddings, run_node2vec
from worker.jobs.anomaly_detection.pipeline import CS_GAD_PAPER_POOLED
from worker.jobs.anomaly_detection.validator import compute_metrics


METHODS = {
    "cs_gad_peer": "CS-GAD paper (peer NN + drift)",
    "org_peer_nn": "Organizational peer NN (vs legitimate baseline only)",
    "org_centroid": "Organizational centroid deviation",
    "combined_org": "Combined graph signals (peer + drift + org peer + org centroid)",
}


def _row_key(row: dict) -> str:
    ws = row["window_start"]
    label = ws.isoformat() if hasattr(ws, "isoformat") else str(ws)
    return f"{row['principal_arn']}::{label}"


def _pool(rows: list[dict]) -> dict:
    flagged = [{"principal_arn": _row_key(r)} for r in rows if r["flagged_as_anomaly"]]
    principals = [{"principal_arn": _row_key(r), "is_attack": r["is_attack"]} for r in rows]
    return compute_metrics(flagged, principals)


def _score_window(method: str, graph, pe, history):
    peer_nn = nn_distance_score(pe, graph)
    drift = drift_score(pe, history)
    org_peer = organizational_peer_nn_score(pe, graph)
    org_cent = organizational_centroid_score(pe)

    if method == "cs_gad_peer":
        combined = combine_scores(peer_nn, drift)
        org = None
    elif method == "org_peer_nn":
        combined = combine_scores(org_peer, drift)
        org = org_peer
    elif method == "org_centroid":
        combined = combine_scores(org_cent, drift)
        org = org_cent
    elif method == "combined_org":
        combined = combine_scores(peer_nn, drift, org_peer, org_cent)
        org = combine_scores(org_peer, org_cent)
    else:
        raise ValueError(method)

    flagged = flag_anomalies_from_combined(
        combined, peer_nn, drift, graph, method=method, org_scores=org
    )
    return combined, flagged


def main() -> None:
    chunk_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"D:\flaws_cloudtrail_logs")
    n_chunks = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    output = Path(
        sys.argv[3]
        if len(sys.argv) > 3
        else ROOT.parent / "output" / "anomaly" / "research_comparison.json"
    )

    graphs, meta, stats = build_graphs_from_chunks(chunk_dir, n_chunks, window_hours=1)
    method_rows: dict[str, list[dict]] = {method: [] for method in METHODS}
    history: dict = {}

    progress_path = output.parent / "research_graph_eval_progress.json"
    total_windows = len(graphs)
    qualifying_target = stats["qualifying_windows"]
    processed = 0
    qualifying_done = 0
    t0 = time.time()

    def write_progress(status: str = "running") -> None:
        elapsed = time.time() - t0
        rate = processed / elapsed if elapsed > 0 and processed else 0.0
        remaining = total_windows - processed
        eta_seconds = remaining / rate if rate > 0 else None
        payload = {
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "total_windows": total_windows,
            "windows_processed": processed,
            "pct_all_windows": round(100.0 * processed / total_windows, 2) if total_windows else 0.0,
            "qualifying_windows_target": qualifying_target,
            "qualifying_windows_scored": qualifying_done,
            "pct_qualifying": round(100.0 * qualifying_done / qualifying_target, 2)
            if qualifying_target
            else 0.0,
            "elapsed_minutes": round(elapsed / 60, 1),
            "eta_minutes": round(eta_seconds / 60, 1) if eta_seconds is not None else None,
            "output_file": str(output),
        }
        progress_path.parent.mkdir(parents=True, exist_ok=True)
        with open(progress_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    write_progress("running")

    for window_start, graph in sorted(graphs.items(), key=lambda x: x[0]):
        pe = get_principal_embeddings(run_node2vec(graph, seed=42), graph)
        history = update_historical_embeddings(history, pe)
        processed += 1

        if len(list(get_principal_nodes(graph))) < 3:
            if processed % 25 == 0 or processed == total_windows:
                write_progress("running")
            continue

        qualifying_done += 1

        per_method_flagged: dict[str, set[str]] = {}
        for method in METHODS:
            _, flagged = _score_window(method, graph, pe, history)
            per_method_flagged[method] = {f["principal_arn"] for f in flagged}

        for node in get_principal_nodes(graph):
            attrs = graph.nodes[node]
            arn = attrs.get("label") or node.removeprefix("P::")
            is_attack = bool(attrs.get("is_attack"))
            for method in METHODS:
                method_rows[method].append(
                    {
                        "window_start": window_start,
                        "principal_arn": arn,
                        "is_attack": is_attack,
                        "flagged_as_anomaly": arn in per_method_flagged[method],
                    }
                )

        if processed % 25 == 0 or processed == total_windows:
            write_progress("running")

    results_by_method: dict[str, dict] = {}
    for method in METHODS:
        results_by_method[method] = {
            "description": METHODS[method],
            "metrics": _pool(method_rows[method]),
        }

    report = {
        "dataset": {
            "chunks": f"0-{n_chunks - 1}",
            "total_events": meta["total_events"],
            "attack_events": meta["attack_events"],
            "qualifying_windows": stats["qualifying_windows"],
            "attack_windows_total": 26,
            "note": (
                "Only 26 hourly windows contain any attack activity. "
                "Graph methods use environment inventory for legitimate actors "
                "(backup, Level6, flaws role, root) — NOT attack labels."
            ),
        },
        "cs_gad_paper_reference": CS_GAD_PAPER_POOLED,
        "methods": results_by_method,
        "research_workflow": [
            "1. Parse CloudTrail into tripartite graphs (Principal-Action-Service)",
            "2. Node2Vec embeddings per time window (CS-GAD hyperparameters)",
            "3. Score anomalies via graph distance (peer / org-baseline / drift)",
            "4. Threshold: mu + 2sigma per window (paper formula, no rule bypass)",
            "5. Evaluate against held-out attack labels on qualifying windows",
        ],
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    write_progress("complete")

    print("=== Research graph methods (qualifying windows, NO IP rules) ===")
    print(f"Events: {meta['total_events']}  Qualifying windows: {stats['qualifying_windows']}")
    print(f"Paper reference: P={CS_GAD_PAPER_POOLED['precision']} F1={CS_GAD_PAPER_POOLED['f1_score']}\n")
    for method, data in results_by_method.items():
        m = data["metrics"]
        print(
            f"{method}: P={m['precision']} R={m['recall']} F1={m['f1_score']} "
            f"Acc={m['accuracy']} TP={m['true_positives']} FP={m['false_positives']} FN={m['false_negatives']}"
        )
    print(f"\nSaved: {output}")


if __name__ == "__main__":
    main()
