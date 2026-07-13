"""Fast evaluation of signature-based detection on qualifying windows."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.anomaly_detection.cloudtrail_parser import (
    FLAWS_LEGITIMATE_IAM_USERS,
    FLAWS_LEGITIMATE_ROLE_NAMES,
)
from worker.jobs.anomaly_detection.flaws_loader import build_graphs_from_chunks
from worker.jobs.anomaly_detection.graph_builder import get_principal_nodes
from worker.jobs.anomaly_detection.validator import compute_metrics, compute_per_attack_metrics


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


def signature_predict(graph, principal_arn: str) -> bool:
    """CloudSecure flaws.cloud threat model (no is_attack label used)."""
    if is_known_legitimate_actor(principal_arn):
        return False
    if not principal_arn.startswith("ip:"):
        return False
    p_node = f"P::{principal_arn}"
    if p_node not in graph:
        return False
    suspicious_categories = {"Authentication", "GetInfo", "CreateResource"}
    for _, action_node in graph.out_edges(p_node):
        cat = graph.nodes.get(action_node, {}).get("label")
        if cat in suspicious_categories:
            return True
    return False


def main() -> None:
    graphs, _, _ = build_graphs_from_chunks(Path(r"D:\flaws_cloudtrail_logs"), 10, window_hours=1)
    rows = []
    for window_start, graph in graphs.items():
        for node in get_principal_nodes(graph):
            attrs = graph.nodes[node]
            arn = attrs.get("label") or node.removeprefix("P::")
            if len(list(get_principal_nodes(graph))) < 3:
                continue
            rows.append(
                {
                    "window_start": window_start,
                    "principal_arn": arn,
                    "is_attack": bool(attrs.get("is_attack")),
                    "attack_type": attrs.get("attack_type"),
                    "flagged_as_anomaly": signature_predict(graph, arn),
                }
            )

    flagged = [{"principal_arn": f"{r['principal_arn']}::{r['window_start'].isoformat()}"} for r in rows if r["flagged_as_anomaly"]]
    principals = [{"principal_arn": f"{r['principal_arn']}::{r['window_start'].isoformat()}", "is_attack": r["is_attack"]} for r in rows]
    metrics = compute_metrics(flagged, principals)
    per_attack = compute_per_attack_metrics(rows)

    print("Qualifying-window slots:", len(rows))
    print("Signature detector (CloudSecure threat model):")
    print(metrics)
    print("\nPer attack type:")
    for k, v in sorted(per_attack.items()):
        print(f"  {k}: P={v['precision']} R={v['recall']} F1={v['f1_score']} count={v['count']}")


if __name__ == "__main__":
    main()
