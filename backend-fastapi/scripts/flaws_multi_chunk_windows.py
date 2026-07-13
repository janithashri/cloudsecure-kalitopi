from worker.jobs.anomaly_detection.action_categoriser import categorise_events
from worker.jobs.anomaly_detection.cloudtrail_parser import get_time_windows, parse_directory
from worker.jobs.anomaly_detection.graph_builder import build_all_windows, get_principal_nodes

events = categorise_events(parse_directory(r"D:\flaws_cloudtrail_logs"))
for hours in (1, 24):
    graphs = build_all_windows(get_time_windows(events, hours), min_events_per_window=5)
    counts = [len(list(get_principal_nodes(g))) for g in graphs.values()]
    ge3 = sum(1 for n in counts if n >= 3)
    print(f"{hours}h: windows={len(counts)} avg={sum(counts)/len(counts):.2f} ge3={100*ge3/len(counts):.1f}%")
