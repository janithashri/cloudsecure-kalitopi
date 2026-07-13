"""Count qualifying hourly windows across flaws.cloud chunks (incremental)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.anomaly_detection.flaws_loader import build_graphs_from_chunks


def main() -> None:
    chunk_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"D:\flaws_cloudtrail_logs")
    n_chunks = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    _, meta, stats = build_graphs_from_chunks(chunk_dir, n_chunks)
    print(f"chunks: 0-{n_chunks - 1}")
    for key in ("total_events", "attack_events", "total_windows"):
        print(f"{key}: {meta[key]}")
    for key, value in stats.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
