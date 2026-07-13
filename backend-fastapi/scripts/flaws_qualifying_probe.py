"""Count qualifying hourly windows (>=3 principals) before full pipeline run."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.anomaly_detection.action_categoriser import categorise_events
from worker.jobs.anomaly_detection.cloudtrail_parser import parse_directory, get_time_windows
from worker.jobs.anomaly_detection.graph_builder import build_all_windows, get_principal_nodes


def main() -> None:
    dataset = sys.argv[1] if len(sys.argv) > 1 else r"D:\flaws_cloudtrail_logs"
    max_chunk = int(sys.argv[2]) if len(sys.argv) > 2 else 9

    root = Path(dataset)
    def chunk_index(path: Path) -> int:
        name = path.name.replace("flaws_cloudtrail", "").replace(".json.gz", "")
        return int(name)

    files = sorted(root.glob("flaws_cloudtrail*.json.gz"))
    files = [f for f in files if chunk_index(f) <= max_chunk]
    print(f"chunks: 0-{max_chunk} ({len(files)} files)")

    from worker.jobs.anomaly_detection.cloudtrail_parser import parse_file

    events = categorise_events([e for f in files for e in parse_file(str(f))])
    windows = get_time_windows(events, window_hours=1)
    graphs = build_all_windows(windows, min_events_per_window=5)

    qualifying = []
    principals_in_qualifying: set[str] = set()
    for window_start, graph in graphs.items():
        principal_nodes = list(get_principal_nodes(graph))
        if len(principal_nodes) < 3:
            continue
        qualifying.append(window_start)
        for node in principal_nodes:
            attrs = graph.nodes[node]
            principals_in_qualifying.add(attrs.get("label") or node.removeprefix("P::"))

    print(f"total_events: {len(events)}")
    print(f"total_hourly_windows: {len(graphs)}")
    print(f"qualifying_windows_ge_3_principals: {len(qualifying)}")
    print(f"distinct_principals_in_qualifying_windows: {len(principals_in_qualifying)}")
    if events:
        print(f"date_range: {events[0]['event_time']} -> {events[-1]['event_time']}")


if __name__ == "__main__":
    main()
