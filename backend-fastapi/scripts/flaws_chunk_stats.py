"""Parse first flaws.cloud gzip chunk and report dataset stats."""

from __future__ import annotations

import gzip
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.anomaly_detection.action_categoriser import categorise_events, get_category_distribution
from worker.jobs.anomaly_detection.cloudtrail_parser import get_time_windows, parse_file
from worker.jobs.anomaly_detection.graph_builder import build_all_windows, get_principal_nodes


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else r"D:\flaws_cloudtrail_logs\flaws_cloudtrail00.json.gz"
    path = Path(target)
    if path.is_dir():
        from worker.jobs.anomaly_detection.cloudtrail_parser import parse_directory

        events = categorise_events(parse_directory(str(path)))
        chunk_label = str(path)
    else:
        events = categorise_events(parse_file(target))
        chunk_label = target
    windows = get_time_windows(events, window_hours=1)
    graphs = build_all_windows(windows, min_events_per_window=5)

    principals_per_window = []
    sufficient_windows = 0
    for window_start, graph in graphs.items():
        n = len(list(get_principal_nodes(graph)))
        principals_per_window.append(n)
        if n >= 3:
            sufficient_windows += 1

    total_windows = len(graphs)
    avg_principals = sum(principals_per_window) / total_windows if total_windows else 0.0
    pct_sufficient = 100.0 * sufficient_windows / total_windows if total_windows else 0.0
    category_distribution = get_category_distribution(events)
    unknown_pct = 100.0 * category_distribution.get("Unknown", 0) / len(events) if events else 0.0

    attack_events = sum(1 for e in events if e["is_attack"])
    print(f"chunk: {chunk_label}")
    print(f"total_events: {len(events)}")
    print(f"attack_events: {attack_events}")
    print(f"normal_events: {len(events) - attack_events}")
    print(f"date_range: {events[0]['event_time']} -> {events[-1]['event_time']}")
    print(f"hourly_windows (min 5 events): {total_windows}")
    print(f"avg_principals_per_window: {avg_principals:.2f}")
    print(f"min_principals_per_window: {min(principals_per_window) if principals_per_window else 0}")
    print(f"max_principals_per_window: {max(principals_per_window) if principals_per_window else 0}")
    print(f"windows_with_ge_3_principals: {sufficient_windows}/{total_windows} ({pct_sufficient:.1f}%)")
    print(f"unknown_category_pct: {unknown_pct:.2f}")
    print("category_distribution:")
    for cat, count in sorted(category_distribution.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")


if __name__ == "__main__":
    main()
