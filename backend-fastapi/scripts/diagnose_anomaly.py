"""Quick diagnostic for flaws.cloud pooled anomaly results."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.anomaly_detection.flaws_loader import build_graphs_from_chunks


def main() -> None:
    results_path = Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else ROOT.parent / "output" / "anomaly" / "flaws_chunks0_9" / "anomaly_results.json"
    )
    chunk_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(r"D:\flaws_cloudtrail_logs")

    r = json.loads(results_path.read_text())
    print("=== Results file ===")
    print("scorable_windows:", r["scorable_windows"])
    print("total_flagged:", r["total_flagged"])
    print("pooled:", r.get("pooled_scorable_metrics"))
    per_window = r["per_window_f1_range"]["values"]
    print("per_window_f1 count:", len(per_window), "nonzero:", sum(1 for x in per_window if x))

    attacks = [x for x in r.get("principal_labels", []) if x.get("is_attack")]
    print("attack principals (global):", len(attacks))
    print("attack types:", Counter(x.get("attack_type") for x in attacks))

    # Build graphs and inspect qualifying windows with attack principals
    print("\n=== Graph analysis (chunks 0-9) ===")
    graphs, meta, stats = build_graphs_from_chunks(chunk_dir, 10, window_hours=1)
    attack_in_qualifying = 0
    attack_windows = 0
    principals_in_qual = 0
    attack_principal_windows = 0

    for window_start, graph in graphs.items():
        principals = [
            (attrs.get("label") or node.removeprefix("P::"), bool(attrs.get("is_attack")))
            for node, attrs in graph.nodes(data=True)
            if attrs.get("node_type") == "principal"
        ]
        if len(principals) < 3:
            continue
        principals_in_qual += len(principals)
        window_has_attack = any(is_a for _, is_a in principals)
        if window_has_attack:
            attack_windows += 1
            attack_in_qualifying += sum(1 for _, is_a in principals if is_a)
            attack_principal_windows += sum(1 for _, is_a in principals if is_a)

    print("qualifying windows:", stats["qualifying_windows"])
    print("principal slots in qualifying windows:", principals_in_qual)
    print("qualifying windows with >=1 attack principal:", attack_windows)
    print("attack principal slots in qualifying windows:", attack_principal_windows)


if __name__ == "__main__":
    main()
