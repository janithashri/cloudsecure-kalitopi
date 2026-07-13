from collections import Counter, defaultdict

from worker.jobs.anomaly_detection.action_categoriser import categorise_events
from worker.jobs.anomaly_detection.cloudtrail_parser import get_time_windows, parse_file

events = categorise_events(parse_file(r"D:\flaws_cloudtrail_logs\flaws_cloudtrail00.json.gz"))
print("unique principals", len(set(e["principal_arn"] for e in events)))
print("unknown principals", sum(1 for e in events if e["principal_arn"] == "unknown"))
print("types", Counter(e["principal_type"] for e in events).most_common())
month_counts = defaultdict(int)
for e in events:
    month_counts[e["event_time"].strftime("%Y-%m")] += 1
print("months", len(month_counts), "top", sorted(month_counts.items(), key=lambda x: -x[1])[:5])
windows = get_time_windows(events, 1)
busiest = max(windows.items(), key=lambda kv: len(kv[1]))
print("busiest hour events", len(busiest[1]), "principals", len(set(e["principal_arn"] for e in busiest[1])))
