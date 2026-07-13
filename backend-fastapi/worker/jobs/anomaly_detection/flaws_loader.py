"""Incremental flaws.cloud chunk loading and pooled pipeline helpers."""

from __future__ import annotations

import gc
from collections import Counter, OrderedDict
from datetime import datetime
from pathlib import Path

from datetime import datetime, timezone

from worker.jobs.anomaly_detection.action_categoriser import categorise_event
from worker.jobs.anomaly_detection.cloudtrail_parser import parse_file_iter
from worker.jobs.anomaly_detection.graph_builder import build_all_windows, get_principal_nodes


def chunk_paths(chunk_dir: Path, n_chunks: int) -> list[Path]:
    paths = [chunk_dir / f"flaws_cloudtrail{i:02d}.json.gz" for i in range(n_chunks)]
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        raise FileNotFoundError(f"Missing chunk files: {missing[:3]}...")
    return paths


def merge_chunks_incrementally(
    chunk_dir: Path,
    n_chunks: int,
    window_hours: int = 1,
    min_events_per_window: int = 5,
) -> tuple[OrderedDict[datetime, list[dict]], dict]:
    """
    Parse each gzip chunk one at a time, merge into hourly windows.
    Keeps peak memory to one chunk JSON + merged window buckets.
    """
    windowed: dict[datetime, list[dict]] = {}
    category_distribution: Counter[str] = Counter()
    total_events = 0
    attack_events = 0

    for path in chunk_paths(chunk_dir, n_chunks):
        chunk_windows: dict[datetime, list[dict]] = {}
        for event in parse_file_iter(str(path)):
            event["action_category"] = categorise_event(event["event_name"])
            total_events += 1
            if event["is_attack"]:
                attack_events += 1
            category_distribution[event.get("action_category") or "Unknown"] += 1
            ts = int(event["event_time"].timestamp())
            window_seconds = max(window_hours, 1) * 3600
            window_start = datetime.fromtimestamp(
                (ts // window_seconds) * window_seconds,
                tz=timezone.utc,
            )
            chunk_windows.setdefault(window_start, []).append(event)
        for window_start, batch in chunk_windows.items():
            windowed.setdefault(window_start, []).extend(batch)
        del chunk_windows
        gc.collect()

    filtered = OrderedDict(
        sorted(
            ((k, v) for k, v in windowed.items() if len(v) >= min_events_per_window),
            key=lambda item: item[0],
        )
    )
    meta = {
        "n_chunks": n_chunks,
        "total_events": total_events,
        "attack_events": attack_events,
        "normal_events": total_events - attack_events,
        "category_distribution": dict(category_distribution),
        "total_windows": len(filtered),
    }
    return filtered, meta


def qualifying_window_stats(windowed_graphs) -> dict:
    qualifying_keys: list[str] = []
    principal_arns: set[str] = set()
    principals_per_window: list[int] = []

    for window_start, graph in windowed_graphs.items():
        principals = []
        for node in get_principal_nodes(graph):
            attrs = graph.nodes[node]
            principals.append(attrs.get("label") or node.removeprefix("P::"))
        n = len(principals)
        principals_per_window.append(n)
        if n >= 3:
            qualifying_keys.append(window_start.isoformat())
            principal_arns.update(principals)

    total = len(windowed_graphs)
    qualifying = len(qualifying_keys)
    return {
        "qualifying_windows": qualifying,
        "pct_qualifying": round(100.0 * qualifying / total, 2) if total else 0.0,
        "distinct_principals_in_qualifying": len(principal_arns),
        "avg_principals_per_window": round(sum(principals_per_window) / total, 2) if total else 0.0,
    }


def build_graphs_from_chunks(chunk_dir: Path, n_chunks: int, window_hours: int = 1) -> tuple[OrderedDict, dict, dict]:
    windowed_events, meta = merge_chunks_incrementally(chunk_dir, n_chunks, window_hours=window_hours)
    graphs = build_all_windows(windowed_events, min_events_per_window=5)
    stats = qualifying_window_stats(graphs)
    return graphs, meta, stats
