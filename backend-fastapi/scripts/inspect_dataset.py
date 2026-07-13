"""Temporary script to inspect CloudTrail dataset structure."""
import json
import glob
import os
from collections import Counter
from pathlib import Path

ROOT = r"C:\Users\Admin\Downloads\aws_dataset-main\aws_dataset-main"


def main():
    files = sorted(glob.glob(os.path.join(ROOT, "**", "*.json"), recursive=True))
    print(f"Total JSON files: {len(files)}")
    print("\nDirectory tree:")
    for p in sorted(Path(ROOT).rglob("*")):
        rel = p.relative_to(ROOT)
        if p.is_dir():
            print(f"  [DIR]  {rel}/")
        elif rel.parent == Path("."):
            print(f"  [FILE] {rel}")

    print("\nSample filenames (first 5, last 3):")
    for f in files[:5]:
        print(f"  {os.path.basename(f)}")
    print("  ...")
    for f in files[-3:]:
        print(f"  {os.path.basename(f)}")

    # Analyze 5 files spread across dataset
    sample_indices = [0, len(files) // 4, len(files) // 2, 3 * len(files) // 4, len(files) - 1]
    sample_files = [files[i] for i in sample_indices]

    all_keys = Counter()
    shapes = Counter()
    total_events = 0
    event_names = Counter()
    principals = set()
    has_error = 0
    event_times = []

    for fp in sample_files:
        print(f"\n=== FILE: {os.path.basename(fp)} ===")
        try:
            with open(fp, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"  MALFORMED JSON: {e}")
            continue

        if isinstance(data, dict):
            if "Records" in data:
                records = data["Records"]
                shapes["dict_with_Records"] += 1
            else:
                records = [data]
                shapes["single_event_dict"] += 1
        elif isinstance(data, list):
            records = data
            shapes["array_of_events"] += 1
        else:
            print(f"  Unexpected type: {type(data)}")
            continue

        print(f"  Events in file: {len(records)}")
        if records:
            ev = records[0]
            print(f"  First record keys ({len(ev)}): {sorted(ev.keys())}")
            print(f"  Sample eventName: {ev.get('eventName')}")
            print(f"  Sample eventTime: {ev.get('eventTime')}")
            ui = ev.get("userIdentity", {})
            print(f"  userIdentity keys: {sorted(ui.keys()) if isinstance(ui, dict) else ui}")
            print(f"  userIdentity.type: {ui.get('type') if isinstance(ui, dict) else None}")
            print(f"  userIdentity.arn: {ui.get('arn') if isinstance(ui, dict) else None}")
            print(f"  eventSource: {ev.get('eventSource')}")
            print(f"  errorCode: {ev.get('errorCode', 'MISSING')}")
            print(f"  errorMessage: {ev.get('errorMessage', 'MISSING')}")

    # Full parse stats
    print("\n=== FULL DATASET SCAN ===")
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            continue

        if isinstance(data, dict):
            records = data.get("Records", [data] if "eventName" in data else [])
        elif isinstance(data, list):
            records = data
        else:
            continue

        total_events += len(records)
        for ev in records:
            all_keys.update(ev.keys())
            event_names[ev.get("eventName", "unknown")] += 1
            ui = ev.get("userIdentity") or {}
            arn = ui.get("arn")
            if not arn:
                sc = ui.get("sessionContext") or {}
                issuer = sc.get("sessionIssuer") or {}
                arn = issuer.get("arn")
            if arn:
                principals.add(arn)
            if ev.get("errorCode"):
                has_error += 1
            et = ev.get("eventTime")
            if et:
                event_times.append(et)

    print(f"Total events: {total_events}")
    print(f"Unique principals: {len(principals)}")
    print(f"Events with errorCode: {has_error}")
    print(f"Date range: {min(event_times) if event_times else 'N/A'} -> {max(event_times) if event_times else 'N/A'}")
    print(f"\nAll unique top-level event keys ({len(all_keys)}):")
    print(sorted(all_keys))
    print(f"\nTop 20 event names:")
    for name, cnt in event_names.most_common(20):
        print(f"  {name}: {cnt}")

    # Attack labeling from paths
    attack_indicators = [
        "privesc", "privilege_escalation", "lateral_movement",
        "exfiltration", "discovery", "persistence", "defense_evasion",
        "credential_access", "initial_access", "execution", "impact",
        "attack", "malicious", "adversary",
    ]
    attack_files = [f for f in files if any(x in f.lower() for x in attack_indicators)]
    baseline_files = [f for f in files if "baseline" in f.lower() or "normal" in f.lower()]
    print(f"\nAttack-indicator paths: {len(attack_files)} files")
    print(f"Baseline/normal paths: {len(baseline_files)} files")

    # Print 5 sample records
    print("\n=== 5 SAMPLE RECORDS ===")
    count = 0
    for fp in files:
        with open(fp, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            records = data.get("Records", [data] if "eventName" in data else [])
        else:
            records = data
        for ev in records:
            print(json.dumps(ev, indent=2, default=str)[:1500])
            print("---")
            count += 1
            if count >= 5:
                return


def analyze_attack_labeling():
    """Identify attack vs normal principals (no folder labels in this dataset)."""
    files = sorted(glob.glob(os.path.join(ROOT, "**", "*.json"), recursive=True))
    principals = Counter()
    stratus_events = Counter()
    normal_users = Counter()

    for fp in files:
        with open(fp, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            records = data.get("Records", [data] if "eventName" in data else [])
        else:
            records = data

        for ev in records:
            ui = ev.get("userIdentity") or {}
            arn = ui.get("arn")
            if not arn:
                sc = ui.get("sessionContext") or {}
                arn = (sc.get("sessionIssuer") or {}).get("arn", "unknown")
            principals[arn] += 1
            arn_lower = arn.lower()
            if any(x in arn_lower for x in ("stratus", "red-team", "redteam", "enumerate")):
                stratus_events[ev.get("eventName", "unknown")] += 1
            elif ui.get("type") == "IAMUser":
                normal_users[arn] += 1

    print("\n=== ATTACK vs NORMAL ANALYSIS ===")
    print("All principals by event count:")
    for arn, cnt in principals.most_common():
        tag = "ATTACK?" if any(x in arn.lower() for x in ("stratus", "red-team", "enumerate")) else "normal?"
        print(f"  {cnt:4d}  [{tag}]  {arn}")

    print(f"\nStratus/red-team principals: {sum(1 for a in principals if any(x in a.lower() for x in ('stratus', 'red-team', 'enumerate')))}")
    print("Top Stratus-related event names:")
    for name, cnt in stratus_events.most_common(15):
        print(f"  {name}: {cnt}")

    print(f"\nIAM user principals (likely baseline): {len(normal_users)}")
    for arn, cnt in normal_users.most_common():
        print(f"  {cnt:4d}  {arn}")


if __name__ == "__main__":
    main()
    analyze_attack_labeling()
