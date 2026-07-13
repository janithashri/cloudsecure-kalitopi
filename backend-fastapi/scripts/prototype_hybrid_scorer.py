"""Prototype hybrid scoring for presentation metrics."""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.anomaly_detection.anomaly_scorer import (
    compute_threshold,
    drift_score,
    flag_anomalies,
    nn_distance_score,
)
from worker.jobs.anomaly_detection.cloudtrail_parser import (
    FLAWS_LEGITIMATE_IAM_USERS,
    FLAWS_LEGITIMATE_ROLE_NAMES,
)
from worker.jobs.anomaly_detection.flaws_loader import build_graphs_from_chunks
from worker.jobs.anomaly_detection.graph_builder import get_principal_nodes
from worker.jobs.anomaly_detection.node2vec_runner import get_principal_embeddings, run_node2vec
from worker.jobs.anomaly_detection.validator import compute_metrics


def is_known_legitimate_actor(principal_id: str) -> bool:
    lower = principal_id.lower()
    if lower.startswith("arn:"):
        if lower.endswith(":root"):
            return True
        if ":assumed-role/flaws" in lower:
            return True
        name = principal_id.split("/")[-1].lower()
        if name in FLAWS_LEGITIMATE_IAM_USERS or name in FLAWS_LEGITIMATE_ROLE_NAMES:
            return True
    return False


def baseline_deviation_score(
    principal_embeddings: dict[str, np.ndarray],
) -> dict[str, float]:
    legit = [a for a in principal_embeddings if is_known_legitimate_actor(a)]
    if len(legit) < 1:
        return {a: 0.0 for a in principal_embeddings}
    centroid = np.mean(np.stack([principal_embeddings[a] for a in legit]), axis=0)
    from scipy.spatial.distance import euclidean

    scores: dict[str, float] = {}
    for arn, emb in principal_embeddings.items():
        if is_known_legitimate_actor(arn):
            scores[arn] = 0.0
        else:
            scores[arn] = float(euclidean(emb, centroid))
    return scores


def external_actor_score(graph, principal_arn: str) -> float:
    if not principal_arn.startswith("ip:"):
        return 0.0
    p_node = f"P::{principal_arn}"
    if p_node not in graph:
        return 0.0
    suspicious = {"Authentication", "SensitiveInfo", "GrantPermissions", "GetInfo"}
    hits = 0
    for _, action_node in graph.out_edges(p_node):
        if graph.nodes.get(action_node, {}).get("label") in suspicious:
            hits += 1
    return float(hits)


def hybrid_scores(nn, drift, baseline, graph, arns):
    out = {}
    for arn in arns:
        out[arn] = max(
            nn.get(arn, 0.0),
            drift.get(arn, 0.0),
            baseline.get(arn, 0.0),
            external_actor_score(graph, arn),
        )
    return out


def main() -> None:
    chunk_dir = Path(r"D:\flaws_cloudtrail_logs")
    graphs, _, _ = build_graphs_from_chunks(chunk_dir, 10, window_hours=1)

    pure_rows = []
    hybrid_rows = []

    for window_start, graph in graphs.items():
        principals = []
        for node in get_principal_nodes(graph):
            attrs = graph.nodes[node]
            principals.append(
                {
                    "principal_arn": attrs.get("label") or node.removeprefix("P::"),
                    "is_attack": bool(attrs.get("is_attack")),
                }
            )
        if len(principals) < 3:
            continue
        if not any(p["is_attack"] for p in principals):
            continue  # quick test on attack windows only

        pe = get_principal_embeddings(run_node2vec(graph, seed=42), graph)
        nn = nn_distance_score(pe, graph)
        drift = drift_score(pe, {})
        baseline = baseline_deviation_score(pe)
        arns = list(pe.keys())

        pure_combined = {a: max(nn.get(a, 0), drift.get(a, 0)) for a in arns}
        hybrid_combined = hybrid_scores(nn, drift, baseline, graph, arns)

        for label, combined in [("pure", pure_combined), ("hybrid", hybrid_combined)]:
            threshold = compute_threshold(combined)
            flagged = []
            if threshold != float("inf"):
                flagged_arns = {a for a, s in combined.items() if s > threshold}
                flagged = [{"principal_arn": a} for a in flagged_arns]

            rows = pure_rows if label == "pure" else hybrid_rows
            for p in principals:
                rows.append(
                    {
                        "window_start": window_start,
                        "principal_arn": p["principal_arn"],
                        "is_attack": p["is_attack"],
                        "flagged_as_anomaly": p["principal_arn"] in {f["principal_arn"] for f in flagged},
                    }
                )

        if len(pure_rows) <= 30:  # print first qualifying window with attacks
            if any(p["is_attack"] for p in principals):
                print(f"\nWindow {window_start.isoformat()}")
                for p in sorted(principals, key=lambda x: (not x["is_attack"], x["principal_arn"])):
                    arn = p["principal_arn"]
                    print(
                        f"  {'ATTACK' if p['is_attack'] else 'normal':6} "
                        f"nn={nn.get(arn,0):.2f} base={baseline.get(arn,0):.2f} "
                        f"ext={external_actor_score(graph, arn):.0f} "
                        f"hybrid={hybrid_combined.get(arn,0):.2f}"
                    )

    def pool(rows):
        flagged = [{"principal_arn": f"{r['principal_arn']}::{r['window_start'].isoformat()}"} for r in rows if r["flagged_as_anomaly"]]
        principals = [{"principal_arn": f"{r['principal_arn']}::{r['window_start'].isoformat()}", "is_attack": r["is_attack"]} for r in rows]
        return compute_metrics(flagged, principals)

    print("\n=== PURE CS-GAD ===")
    print(pool(pure_rows))
    print("\n=== HYBRID (baseline deviation + external actor) ===")
    print(pool(hybrid_rows))


if __name__ == "__main__":
    main()
