import gzip
import json
from collections import Counter

path = r"D:\flaws_cloudtrail_logs\flaws_cloudtrail00.json.gz"
with gzip.open(path, "rt", encoding="utf-8") as f:
    recs = json.load(f)["Records"]

human_types = {"IAMUser", "AssumedRole", "Root", "FederatedUser", "SAMLUser", "WebIdentityUser"}
filtered = [r for r in recs if (r.get("userIdentity") or {}).get("type") in human_types]
print("human identity events", len(filtered), "of", len(recs))
print("unique ARNs", len(set((r.get("userIdentity") or {}).get("arn") for r in filtered if (r.get("userIdentity") or {}).get("arn"))))
print("unique source IPs", len(set(r.get("sourceIPAddress") for r in filtered)))
print("unique user agents", len(set(r.get("userAgent") for r in filtered if r.get("userAgent"))))
print("event types", Counter((r.get("userIdentity") or {}).get("type") for r in filtered).most_common())
print("top event names on non-legit suspicious", Counter(
    r["eventName"] for r in filtered
    if r["eventName"] in {"AssumeRole", "GetBucketAcl", "RunInstances", "ConsoleLogin"}
).most_common())
