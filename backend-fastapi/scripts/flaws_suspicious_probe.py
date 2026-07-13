from worker.jobs.anomaly_detection.action_categoriser import categorise_events
from worker.jobs.anomaly_detection.cloudtrail_parser import parse_file, FLAWS_SUSPICIOUS_EVENT_NAMES, _is_legitimate_flaws_principal
from collections import Counter

import gzip, json
path = r"D:\flaws_cloudtrail_logs\flaws_cloudtrail00.json.gz"
with gzip.open(path, "rt", encoding="utf-8") as f:
    recs = json.load(f)["Records"]

susp = []
for r in recs:
    ui = r.get("userIdentity") or {}
    ptype = ui.get("type") or "unknown"
    arn = ui.get("arn") or "unknown"
    if ui.get("type") in {"AWSService", "AWSAccount"}:
        continue
    if r.get("eventName") in FLAWS_SUSPICIOUS_EVENT_NAMES and not _is_legitimate_flaws_principal(arn, ptype):
        susp.append(r)
print("suspicious human events", len(susp))
print("unique ips", len(set(r.get("sourceIPAddress") for r in susp)))
print("unique arns", len(set((r.get("userIdentity") or {}).get("arn") for r in susp)))
print("arn counter", Counter((r.get("userIdentity") or {}).get("arn") for r in susp).most_common(10))
