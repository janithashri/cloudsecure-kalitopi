"""
Check progress of long-running anomaly pipeline jobs.

Usage:
  python scripts/check_pipeline_progress.py
  python scripts/check_pipeline_progress.py --watch
  python scripts/check_pipeline_progress.py --watch 30
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT.parent / "output" / "anomaly"


def _read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _python_jobs() -> list[str]:
    try:
        result = subprocess.run(
            ["wmic", "process", "where", "name='python.exe'", "get", "CommandLine"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        lines = [ln.strip() for ln in result.stdout.splitlines() if ln.strip() and ln.strip() != "CommandLine"]
        return [ln for ln in lines if "anomaly" in ln.lower() or "flaws" in ln.lower() or "research_graph" in ln.lower()]
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return []


def _parse_node2vec_log(log_path: Path) -> dict | None:
    if not log_path.is_file():
        return None
    try:
        text = log_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    matches = re.findall(r"Node2Vec windows:\s+\s*(\d+)%.*?(\d+)/(\d+)", text)
    if not matches:
        return None
    pct, current, total = matches[-1]
    return {
        "phase": "Node2Vec",
        "pct": int(pct),
        "current": int(current),
        "total": int(total),
        "log": str(log_path),
    }


def _print_section(title: str, body: str) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    print(body)


def check_once() -> None:
    jobs = _python_jobs()
    if jobs:
        _print_section("Running Python jobs", "\n".join(f"  • {j}" for j in jobs))
    else:
        _print_section("Running Python jobs", "  (none detected)")

    progress = _read_json(OUTPUT / "research_graph_eval_progress.json")
    if progress:
        _print_section(
            "Research graph eval",
            (
                f"  status: {progress.get('status')}\n"
                f"  all windows: {progress.get('windows_processed')}/{progress.get('total_windows')} "
                f"({progress.get('pct_all_windows')}%)\n"
                f"  qualifying scored: {progress.get('qualifying_windows_scored')}/"
                f"{progress.get('qualifying_windows_target')} ({progress.get('pct_qualifying')}%)\n"
                f"  elapsed: {progress.get('elapsed_minutes')} min"
                + (
                    f"  ETA: ~{progress.get('eta_minutes')} min"
                    if progress.get("eta_minutes") is not None
                    else ""
                )
                + f"\n  updated: {progress.get('updated_at')}"
            ),
        )
    else:
        _print_section("Research graph eval", "  no progress file yet (job not started or still loading chunks)")

    research_out = OUTPUT / "research_comparison.json"
    if research_out.is_file():
        _print_section("Research graph eval", f"  COMPLETE → {research_out}")

    for name in ("flaws_chunks0_9_v2_run.log", "flaws_chunks0_9_run.log"):
        parsed = _parse_node2vec_log(OUTPUT / name)
        if parsed:
            _print_section(
                f"Pooled pipeline log ({name})",
                f"  {parsed['phase']}: {parsed['current']}/{parsed['total']} ({parsed['pct']}%)",
            )

    for label, path in (
        ("flaws v2 summary", OUTPUT / "flaws_chunks0_9_v2" / "pooled_summary.json"),
        ("flaws v1 summary", OUTPUT / "flaws_chunks0_9" / "pooled_summary.json"),
        ("presentation (ignore for research)", OUTPUT / "presentation_metrics" / "presentation_summary.json"),
    ):
        data = _read_json(path)
        if data and "pooled_scorable_metrics" in data:
            m = data["pooled_scorable_metrics"]
            _print_section(
                label,
                f"  F1={m.get('f1_score')}  P={m.get('precision')}  R={m.get('recall')}  (done)",
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Check anomaly pipeline progress")
    parser.add_argument("--watch", nargs="?", const=10, type=int, metavar="SECONDS", help="Refresh every N seconds")
    args = parser.parse_args()

    if args.watch:
        try:
            while True:
                print("\033c", end="")
                print(f"=== Pipeline progress (refresh every {args.watch}s, Ctrl+C to stop) ===")
                check_once()
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        check_once()


if __name__ == "__main__":
    main()
