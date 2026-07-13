from worker.jobs.anomaly_detection.action_categoriser import categorise_events
from worker.jobs.anomaly_detection.cloudtrail_parser import get_time_windows, parse_file
from worker.jobs.anomaly_detection.graph_builder import build_all_windows, get_principal_nodes


def stats_for(events, window_hours, label):
    windows = get_time_windows(events, window_hours=window_hours)
    graphs = build_all_windows(windows, min_events_per_window=5)
    counts = [len(list(get_principal_nodes(g))) for g in graphs.values()]
    total = len(counts)
    ge3 = sum(1 for n in counts if n >= 3)
    print(
        f"{label}: events={len(events)} windows={total} avg_principals={sum(counts)/total if total else 0:.2f} "
        f"ge3={ge3}/{total} ({100*ge3/total if total else 0:.1f}%) max={max(counts) if counts else 0}"
    )


events = categorise_events(parse_file(r"D:\flaws_cloudtrail_logs\flaws_cloudtrail00.json.gz"))
stats_for(events, 1, "full chunk hourly")
stats_for(events, 24, "full chunk daily")
may2017 = [e for e in events if e["event_time"].strftime("%Y-%m") == "2017-05"]
stats_for(may2017, 1, "2017-05 hourly")
