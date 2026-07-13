"""Compare signature variants for presentation metrics."""
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
from worker.jobs.anomaly_detection.validator import compute_metrics


def is_legit(principal_id: str) -> bool:
    lower = principal_id.lower()
    if lower.startswith("arn:"):
        if lower.endswith(":root") or ":assumed-role/flaws" in lower:
            return True
        name = principal_id.split("/")[-1].lower()
        if name in FLAWS_LEGITIMATE_IAM_USERS or name in FLAWS_LEGITIMATE_ROLE_NAMES:
            return True
    return False


def predict(graph, arn: str, categories: set[str]) -> bool:
    if is_legit(arn) or not arn.startswith("ip:"):
        return False
    p_node = f"P::{arn}"
    if p_node not in graph:
        return False
    cats = {graph.nodes[a].get("label") for _, a in graph.out_edges(p_node)}
    return bool(cats & categories)


def eval_variant(graphs, name: str, categories: set[str]) -> None:
    rows = []
    for window_start, graph in graphs.items():
        if len(list(get_principal_nodes(graph))) < 3:
            continue
        for node in get_principal_nodes(graph):
            attrs = graph.nodes[node]
            arn = attrs.get("label") or node.removeprefix("P::")
            flagged = predict(graph, arn, categories)
            rows.append(
                {
                    "window_start": window_start,
                    "principal_arn": arn,
                    "is_attack": bool(attrs.get("is_attack")),
                    "flagged_as_anomaly": flagged,
                }
            )
    flagged = [{"principal_arn": f"{r['principal_arn']}::{r['window_start'].isoformat()}"} for r in rows if r["flagged_as_anomaly"]]
    principals = [{"principal_arn": f"{r['principal_arn']}::{r['window_start'].isoformat()}", "is_attack": r["is_attack"]} for r in rows]
    m = compute_metrics(flagged, principals)
    print(f"{name}: P={m['precision']} R={m['recall']} F1={m['f1_score']} Acc={m['accuracy']} FPR={m['false_positive_rate']}")


def main() -> None:
    graphs, _, _ = build_graphs_from_chunks(Path(r"D:\flaws_cloudtrail_logs"), 10, window_hours=1)
    eval_variant(graphs, "Auth only (external)", {"Authentication"})
    eval_variant(graphs, "Auth+GetInfo (external)", {"Authentication", "GetInfo"})
    eval_variant(graphs, "Auth+GetInfo+Create (external)", {"Authentication", "GetInfo", "CreateResource"})


if __name__ == "__main__":
    main()
