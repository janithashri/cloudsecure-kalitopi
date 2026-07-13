import gzip
import json
from collections import Counter

path = r"D:\flaws_cloudtrail_logs\flaws_cloudtrail00.json.gz"
with gzip.open(path, "rt", encoding="utf-8") as f:
    data = json.load(f)
recs = data["Records"]
unknown = [r for r in recs if not (r.get("userIdentity") or {}).get("arn")]
print("records without arn", len(unknown))
print("sample types", Counter((r.get("userIdentity") or {}).get("type") for r in unknown).most_common(5))
for r in unknown[:3]:
    print(json.dumps(r.get("userIdentity"), indent=2)[:500])
print("--- with arn samples ---")
with_arn = [r for r in recs if (r.get("userIdentity") or {}).get("arn")][:3]
for r in with_arn:
    ui = r.get("userIdentity") or {}
    print(r["eventName"], ui.get("type"), ui.get("arn"))
