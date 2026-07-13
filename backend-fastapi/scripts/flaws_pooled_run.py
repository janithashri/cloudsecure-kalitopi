"""
Run pooled anomaly detection on flaws.cloud chunks 0..N-1 (hourly windows).

Usage:
  python scripts/flaws_pooled_run.py [chunk_dir] [n_chunks] [output_dir]

Phase 1: print qualifying window stats (>=3 principals).
Phase 2: run full Node2Vec + scoring pipeline on pooled qualifying windows.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.anomaly_detection.flaws_loader import build_graphs_from_chunks
from worker.jobs.anomaly_detection.pipeline import run_anomaly_pipeline_from_chunks

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    chunk_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"D:\flaws_cloudtrail_logs")
    n_chunks = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    output_dir = (
        sys.argv[3]
        if len(sys.argv) > 3
        else str(
            ROOT.parent / "output" / "anomaly" / f"flaws_chunks0_{n_chunks - 1}"
        )
    )
    min_qualifying = 300

    print("=== Phase 1: qualifying window stats (no Node2Vec) ===")
    _, meta, stats = build_graphs_from_chunks(chunk_dir, n_chunks, window_hours=1)
    print(f"chunks: 0-{n_chunks - 1}")
    print(f"total_events: {meta['total_events']}")
    print(f"attack_events: {meta['attack_events']}")
    print(f"total_hourly_windows: {meta['total_windows']}")
    print(f"qualifying_windows_ge_3_principals: {stats['qualifying_windows']}")
    print(f"distinct_principals_in_qualifying_windows: {stats['distinct_principals_in_qualifying']}")
    print(f"pct_qualifying: {stats['pct_qualifying']}%")
    print(f"avg_principals_per_window: {stats['avg_principals_per_window']}")

    if stats["qualifying_windows"] < min_qualifying:
        print(
            f"\nSTOP: {stats['qualifying_windows']} qualifying windows < {min_qualifying}. "
            "Scale to 15-20 chunks before running full pipeline."
        )
        sys.exit(1)

    print("\n=== Phase 2: full pooled pipeline (Node2Vec + scoring) ===")
    results = run_anomaly_pipeline_from_chunks(
        str(chunk_dir),
        n_chunks,
        output_dir,
        window_hours=1,
        min_qualifying_windows=min_qualifying,
    )

    print("\n=== Final pooled results ===")
    print(f"metrics_ready: {results['metrics_ready']}")
    print(f"scorable_windows: {results['scorable_windows']}")
    print(f"distinct_principals_in_qualifying_windows: {results['distinct_principals_in_qualifying_windows']}")
    print(f"embedding_stability: {results['embedding_stability'].get('stable_flagged_status_pct')}% passed={results['embedding_stability'].get('passed')}")

    pooled = results.get("pooled_scorable_metrics") or {}
    macro = results.get("macro_pooled_metrics") or {}
    f1_range = results.get("per_window_f1_range") or {}
    print(f"qualifying windows: {results.get('qualifying_windows')}")
    print(f"scorable windows: {results.get('scorable_windows')}")
    print(f"principal slots in qualifying: {results.get('principal_slots_in_qualifying')}")
    print(f"attack principal slots in qualifying: {results.get('attack_principal_slots_in_qualifying')}")
    print(f"qualifying windows with attacks: {results.get('qualifying_windows_with_attacks')}")
    print(f"pooled F1 (micro): {pooled.get('f1_score')}  precision: {pooled.get('precision')}  recall: {pooled.get('recall')}  FPR: {pooled.get('false_positive_rate')}")
    print(f"pooled F1 (macro): {macro.get('f1_score')}  precision: {macro.get('precision')}  recall: {macro.get('recall')}  FPR: {macro.get('false_positive_rate')}")
    print(f"per-window F1 range: {f1_range.get('min')} – {f1_range.get('max')}")

    notes = results.get("comparison_notes", {})
    paper = notes.get("cs_gad_paper_pooled", {})
    stratus = notes.get("stratus_invictus_pooled", {})
    print(f"\nCS-GAD paper pooled F1: {paper.get('f1_score')}  |  Stratus/invictus F1: {stratus.get('f1_score')}")
    print(f"Results saved: {Path(output_dir) / 'anomaly_results.json'}")

    summary_path = Path(output_dir) / "pooled_summary.json"
    summary = {
        "chunks": f"0-{n_chunks - 1}",
        "total_events": meta["total_events"],
        "qualifying_windows_ge_3_principals": stats["qualifying_windows"],
        "distinct_principals_in_qualifying": stats["distinct_principals_in_qualifying"],
        "metrics_ready": results["metrics_ready"],
        "attack_principal_slots_in_qualifying": results.get("attack_principal_slots_in_qualifying"),
        "pooled_scorable_metrics": pooled,
        "macro_pooled_metrics": macro,
        "per_window_f1_range": {
            "min": f1_range.get("min"),
            "max": f1_range.get("max"),
        },
        "comparison_notes": notes,
    }
    with open(summary_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
    print(f"Summary saved: {summary_path}")


if __name__ == "__main__":
    main()
