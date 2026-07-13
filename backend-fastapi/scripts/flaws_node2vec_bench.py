import time
from worker.jobs.anomaly_detection.action_categoriser import categorise_events
from worker.jobs.anomaly_detection.cloudtrail_parser import get_time_windows, parse_file
from worker.jobs.anomaly_detection.graph_builder import build_all_windows
from worker.jobs.anomaly_detection.node2vec_runner import run_node2vec

events = categorise_events(parse_file(r"D:\flaws_cloudtrail_logs\flaws_cloudtrail00.json.gz"))
graphs = build_all_windows(get_time_windows(events, 1), min_events_per_window=5)
graph = next(iter(graphs.values()))
start = time.time()
run_node2vec(graph, seed=42)
print("seconds", round(time.time() - start, 2), "nodes", graph.number_of_nodes(), "windows_total", len(graphs))
