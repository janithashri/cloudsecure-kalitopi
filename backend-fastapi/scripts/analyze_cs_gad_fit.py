"""Dataset analysis: what CS-GAD needs vs what flaws.cloud provides."""
from __future__ import annotations

import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.anomaly_detection.anomaly_scorer import is_known_legitimate_flaws_actor
from worker.jobs.anomaly_detection.flaws_loader import build_graphs_from_chunks
from worker.jobs.anomaly_detection.graph_builder import get_principal_nodes


def main() -> None:
    chunk_dir = Path(r"D:\flaws_cloudtrail_logs")
    graphs, meta, stats = build_graphs_from_chunks(chunk_dir, 10, window_hours=1)

    attack_by_window_size = Counter()
    attack_slots = 0
    legit_in_qualifying = 0
    external_in_qualifying = 0
    attack_external = 0
    attack_legit_label = 0

    windows_with_attack = 0
    attack_in_non_qualifying = 0
    attack_in_qualifying = 0

    for graph in graphs.values():
        principals = []
        for node in get_principal_nodes(graph):
            attrs = graph.nodes[node]
            arn = attrs.get("label") or node.removeprefix("P::")
            is_attack = bool(attrs.get("is_attack"))
            principals.append((arn, is_attack))

        n = len(principals)
        if any(p[1] for p in principals):
            windows_with_attack += 1
            attack_by_window_size[n] += 1
            if n >= 3:
                attack_in_qualifying += sum(1 for _, a in principals if a)
            else:
                attack_in_non_qualifying += sum(1 for _, a in principals if a)

        if n < 3:
            continue

        for arn, is_attack in principals:
            if is_attack:
                attack_slots += 1
                if arn.startswith("ip:"):
                    attack_external += 1
                else:
                    attack_legit_label += 1
            if is_known_legitimate_flaws_actor(arn):
                legit_in_qualifying += 1
            if arn.startswith("ip:"):
                external_in_qualifying += 1

    print("=== flaws.cloud dataset (chunks 0-9, hourly) ===")
    print(f"total_events: {meta['total_events']}")
    print(f"attack_events: {meta['attack_events']}")
    print(f"total_windows: {meta['total_windows']}")
    print(f"qualifying_windows (>=3 principals): {stats['qualifying_windows']}")
    print(f"windows_with_any_attack: {windows_with_attack}")
    print(f"attack_slots_in_qualifying: {attack_in_qualifying}")
    print(f"attack_slots_in_non_qualifying (<3 principals): {attack_in_non_qualifying}")
    print(f"pct_attack_slots_in_qualifying: {100*attack_in_qualifying/(attack_in_qualifying+attack_in_non_qualifying):.1f}%")
    print()
    print("Attack windows by principal count:")
    for size in sorted(attack_by_window_size):
        print(f"  {size} principals: {attack_by_window_size[size]} windows")
    print()
    print("In qualifying windows:")
    print(f"  external (ip:) principals in attack slots: {attack_external}/{attack_slots}")
    print(f"  legitimate-bucket attack labels: {attack_legit_label}")
    print(f"  known legitimate actors present: {legit_in_qualifying} slots")
    print(f"  external actor slots total: {external_in_qualifying}")


if __name__ == "__main__":
    main()
