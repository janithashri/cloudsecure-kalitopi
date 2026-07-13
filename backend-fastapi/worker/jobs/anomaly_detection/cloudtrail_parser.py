"""
Parses raw CloudTrail JSON files into a flat list of structured event dicts.
Handles both single-record files and CloudTrail log files with 'Records' array.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

ATTACK_INDICATORS = [
    "privesc",
    "privilege_escalation",
    "lateral_movement",
    "exfiltration",
    "discovery",
    "persistence",
    "defense_evasion",
    "credential_access",
    "initial_access",
    "execution",
    "impact",
    "attack",
    "malicious",
    "adversary",
]

# flaws.cloud legitimate principals (Summit Route training environment)
FLAWS_LEGITIMATE_IAM_USERS = {"backup", "level6"}
FLAWS_LEGITIMATE_ROLE_NAMES = {"flaws"}

# Suspicious API calls performed by external attackers against training levels
FLAWS_SUSPICIOUS_EVENT_NAMES = {
    "AssumeRole",
    "GetBucketAcl",
    "RunInstances",
    "ConsoleLogin",
}

FLAWS_EVENT_ATTACK_TYPES = {
    "AssumeRole": "lateral_movement",
    "GetBucketAcl": "vulnerability_scan",
    "RunInstances": "cryptojacking",
    "ConsoleLogin": "credential_theft",
}

TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
)


def _parse_event_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("+0000"):
        text = text[:-5] + "+00:00"
    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        logger.warning("Could not parse eventTime: %s", value)
        return None


def _extract_records(data: object) -> list[dict]:
    if isinstance(data, dict):
        if "Records" in data and isinstance(data["Records"], list):
            return [r for r in data["Records"] if isinstance(r, dict)]
        if "eventName" in data:
            return [data]
        return []
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def _strip_event_source(event_source: str | None) -> str:
    if not event_source:
        return "unknown"
    return event_source.replace(".amazonaws.com", "")


def _principal_from_event(raw: dict) -> tuple[str, str, str]:
    ui = raw.get("userIdentity") or {}
    principal_type = ui.get("type") or "unknown"
    account_id = ui.get("accountId") or raw.get("recipientAccountId") or "unknown"
    arn = ui.get("arn")
    if not arn:
        session_context = ui.get("sessionContext") or {}
        issuer = session_context.get("sessionIssuer") or {}
        arn = issuer.get("arn")
    if not arn:
        user_name = ui.get("userName")
        if user_name:
            arn = f"arn:aws:iam::{account_id}:user/{user_name}"
    if not arn:
        arn = "unknown"
    return arn, principal_type, account_id


def _resolve_principal_id(raw: dict, arn: str, principal_type: str) -> str:
    """
    flaws.cloud mixes stable IAM ARNs with thousands of ephemeral attacker IPs.
    Known legitimate actors keep their ARN; all others are keyed by IP + user-agent.
    """
    if _is_legitimate_flaws_principal(arn, principal_type):
        return arn
    source_ip = raw.get("sourceIPAddress") or "unknown"
    user_agent = (raw.get("userAgent") or "unknown")[:120]
    return f"ip:{source_ip}|ua:{user_agent}"


def _principal_name_from_arn(arn: str) -> str | None:
    if not arn or arn == "unknown":
        return None
    lower = arn.lower()
    if lower.endswith(":root"):
        return "root"
    if ":assumed-role/" in lower:
        parts = arn.split("/")
        if len(parts) >= 2:
            return parts[-2].lower()
    if ":user/" in lower:
        return arn.split("/")[-1].lower()
    if ":role/" in lower:
        return arn.split("/")[-1].lower()
    return None


def _is_legitimate_flaws_principal(principal_arn: str, principal_type: str) -> bool:
    """Known legitimate flaws.cloud principals per Summit Route writeup."""
    name = _principal_name_from_arn(principal_arn)
    if name == "root":
        return True
    if name in FLAWS_LEGITIMATE_IAM_USERS:
        return True
    if name in FLAWS_LEGITIMATE_ROLE_NAMES:
        return True
    if "assumed-role/flaws" in principal_arn.lower():
        return True
    if principal_type == "Root":
        return True
    return False


def _label_attack(raw: dict, principal_arn: str, principal_type: str) -> tuple[bool, str | None]:
    """
    flaws.cloud ground truth:
    - Legitimate: backup, Level6, flaws role, root (mostly admin)
    - Attack: any other principal performing AssumeRole, GetBucketAcl,
      RunInstances, or ConsoleLogin against the training environment
    """
    if _is_legitimate_flaws_principal(principal_arn, principal_type):
        return False, None

    event_name = raw.get("eventName") or ""
    if event_name in FLAWS_SUSPICIOUS_EVENT_NAMES:
        return True, FLAWS_EVENT_ATTACK_TYPES.get(event_name, "attacker_activity")
    return False, None


def _normalise_event(raw: dict, filepath: str) -> dict | None:
    event_time = _parse_event_time(raw.get("eventTime"))
    if event_time is None:
        return None

    principal_arn, principal_type, account_id = _principal_from_event(raw)
    if principal_type in {"AWSService", "AWSAccount"}:
        return None

    principal_id = _resolve_principal_id(raw, principal_arn, principal_type)
    is_attack, attack_type = _label_attack(raw, principal_arn, principal_type)

    return {
        "event_time": event_time,
        "principal_arn": principal_id,
        "raw_principal_arn": principal_arn,
        "principal_type": principal_type,
        "account_id": account_id,
        "event_name": raw.get("eventName") or "unknown",
        "event_source": _strip_event_source(raw.get("eventSource")),
        "aws_region": raw.get("awsRegion") or "unknown",
        "source_ip": raw.get("sourceIPAddress") or "unknown",
        "user_agent": raw.get("userAgent") or "unknown",
        "error_code": raw.get("errorCode"),
        "error_message": raw.get("errorMessage"),
        "is_attack": is_attack,
        "attack_type": attack_type,
        "source_file": filepath,
    }


def _open_json(filepath: str):
    path = Path(filepath)
    if path.suffix == ".gz" or str(path).endswith(".json.gz"):
        return gzip.open(filepath, "rt", encoding="utf-8")
    return open(filepath, "r", encoding="utf-8")


def parse_file_iter(filepath: str):
    """Stream-parse CloudTrail records without loading the entire file into memory."""
    path = Path(filepath)
    is_gz = path.suffix == ".gz" or str(path).endswith(".json.gz")

    if is_gz:
        try:
            import ijson
        except ImportError as exc:
            raise ImportError(
                "ijson is required for streaming .json.gz CloudTrail files. "
                "Install with: pip install ijson"
            ) from exc
        try:
            with gzip.open(filepath, "rb") as handle:
                for raw in ijson.items(handle, "Records.item"):
                    if isinstance(raw, dict):
                        parsed = _normalise_event(raw, filepath)
                        if parsed:
                            yield parsed
        except OSError as exc:
            logger.warning("Could not read %s: %s", filepath, exc)
        except ijson.common.IncompleteJSONError as exc:
            logger.warning("Malformed JSON in %s: %s", filepath, exc)
        return

    try:
        with _open_json(filepath) as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        logger.warning("Malformed JSON in %s: %s", filepath, exc)
        return
    except OSError as exc:
        logger.warning("Could not read %s: %s", filepath, exc)
        return

    for raw in _extract_records(data):
        parsed = _normalise_event(raw, filepath)
        if parsed:
            yield parsed


def parse_file(filepath: str) -> list[dict]:
    """Returns list of event dicts from one JSON or gzipped JSON file."""
    return list(parse_file_iter(filepath))


def _iter_dataset_files(root: Path) -> list[Path]:
    files = sorted(set(root.rglob("*.json.gz")) | set(root.rglob("*.json")))
    return [path for path in files if not str(path).endswith(".json.gz.json")]


def parse_directory(directory: str) -> list[dict]:
    """Returns list of event dicts from all JSON files in directory tree."""
    root = Path(directory)
    if not root.is_dir():
        logger.warning("Directory not found: %s", directory)
        return []

    events: list[dict] = []
    for path in _iter_dataset_files(root):
        events.extend(parse_file(str(path)))
    events.sort(key=lambda e: e["event_time"])
    return events


def get_time_windows(
    events: list[dict],
    window_hours: int = 1,
) -> OrderedDict[datetime, list[dict]]:
    """
    Groups events by time window.
    Key: window start time (floor to hour)
    Value: list of events in that window
    Returns OrderedDict sorted by time.
    """
    window_seconds = max(window_hours, 1) * 3600
    windows: dict[datetime, list[dict]] = {}
    for event in events:
        event_time: datetime = event["event_time"]
        ts = int(event_time.timestamp())
        window_start = datetime.fromtimestamp(
            (ts // window_seconds) * window_seconds,
            tz=timezone.utc,
        )
        windows.setdefault(window_start, []).append(event)

    return OrderedDict(sorted(windows.items(), key=lambda item: item[0]))


if __name__ == "__main__":
    import sys
    from collections import Counter

    dataset_dir = (
        sys.argv[1]
        if len(sys.argv) > 1
        else r"C:\Users\Admin\Downloads\aws_dataset-main\aws_dataset-main"
    )

    json_files = list(Path(dataset_dir).rglob("*.json"))
    events = parse_directory(dataset_dir)

    attack_events = sum(1 for e in events if e["is_attack"])
    normal_events = len(events) - attack_events
    principals = {e["principal_arn"] for e in events}
    event_names = Counter(e["event_name"] for e in events)
    times = [e["event_time"] for e in events]

    print(f"Total files found: {len(json_files)}")
    print(f"Total events parsed: {len(events)}")
    print(f"Events labelled is_attack=True: {attack_events}")
    print(f"Events labelled is_attack=False: {normal_events}")
    print(f"Unique principal ARNs: {len(principals)}")
    print("Unique event names (first 20):")
    for name, _ in event_names.most_common(20):
        print(f"  {name}")
    if times:
        print(f"Date range: {min(times).isoformat()} -> {max(times).isoformat()}")
