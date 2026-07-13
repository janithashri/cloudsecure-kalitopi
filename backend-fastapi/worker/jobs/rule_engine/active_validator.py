"""
Active behavioral validation, reproducing "Alert or Noise?" (arXiv 2508.12584)
methodology for resource classes not covered by graph-based network exposure
(Feature 2 / Dijkstra hops_from_internet): S3 bucket policy exposure and
IAM access key liveness. All probes are read-only, scoped, rate-limited,
and time-bounded per the paper's Section 3.2.4 safety constraints.
"""
import logging
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

PROBE_TIMEOUT_SECONDS = 5  # matches paper's 5-second per-probe limit
VALIDATION_TAG = "CloudSecureValidationProbe"  # paper's "tagging and transparency" requirement
MAX_PROBES_PER_MINUTE = 20

_rate_lock = threading.Lock()
_probe_timestamps: list[float] = []
_probed_resources: set[str] = set()


def _rate_limit_ok(resource_key: str) -> bool:
    """At most 1 probe per resource per scan; at most 20 probes per minute total."""
    now = time.time()
    with _rate_lock:
        if resource_key in _probed_resources:
            logger.info("Validation probe skipped (already probed this scan): %s", resource_key)
            return False
        cutoff = now - 60.0
        while _probe_timestamps and _probe_timestamps[0] < cutoff:
            _probe_timestamps.pop(0)
        if len(_probe_timestamps) >= MAX_PROBES_PER_MINUTE:
            logger.warning("Validation probe rate limit reached (%s/min)", MAX_PROBES_PER_MINUTE)
            return False
        _probe_timestamps.append(now)
        _probed_resources.add(resource_key)
        return True


def reset_probe_state() -> None:
    """Reset per-scan probe tracking (call at start of each inventory/rule run)."""
    with _rate_lock:
        _probed_resources.clear()


def validate_s3_exposure(bucket_name: str, region: str) -> dict:
    """
    Probe Action per Paper B Table 2: unauthenticated HEAD/GET.
    TP if unauth GET succeeds; FP if all blocked (compensating control exists).
    """
    resource_key = f"s3:{bucket_name}"
    if not _rate_limit_ok(resource_key):
        return {
            "probe_type": "s3_unauth_head_get",
            "resource": bucket_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "classification": "inconclusive",
            "compensating_control": "rate_limit_exceeded",
            "validation_tag": VALIDATION_TAG,
        }

    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config

    start = time.time()
    anon_client = boto3.client(
        "s3",
        region_name=region,
        config=Config(
            signature_version=UNSIGNED,
            connect_timeout=PROBE_TIMEOUT_SECONDS,
            read_timeout=PROBE_TIMEOUT_SECONDS,
        ),
    )
    result = {
        "probe_type": "s3_unauth_head_get",
        "resource": bucket_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "classification": "inconclusive",
        "http_status": None,
        "duration_ms": None,
        "compensating_control": None,
        "validation_tag": VALIDATION_TAG,
    }
    try:
        anon_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
        result.update({"classification": "true_positive", "http_status": 200})
    except Exception as e:
        code = ""
        if hasattr(e, "response") and isinstance(e.response, dict):
            code = e.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "403"):
            result.update(
                {
                    "classification": "false_positive",
                    "http_status": 403,
                    "compensating_control": "bucket_policy_or_acl_denies_anonymous_access",
                }
            )
        elif code == "NoSuchBucket":
            result.update({"classification": "inconclusive", "compensating_control": "bucket_not_found"})
        else:
            result.update(
                {
                    "classification": "inconclusive",
                    "compensating_control": f"probe_error:{code or str(e)[:80]}",
                }
            )
    result["duration_ms"] = round((time.time() - start) * 1000, 1)
    logger.info(
        "S3 validation probe bucket=%s classification=%s duration_ms=%s tag=%s",
        bucket_name,
        result["classification"],
        result["duration_ms"],
        VALIDATION_TAG,
    )
    return result


def validate_iam_key_exposure(access_key_id: str, iam_client) -> dict:
    """
    Probe Action per Paper B Table 2: get-access-key-last-used.
    TP if key active & used recently; FP if inactive/never used.
    Read-only IAM call — never attempts sts:AssumeRole with the flagged key.
    """
    resource_key = f"iam_key:{access_key_id}"
    if not _rate_limit_ok(resource_key):
        return {
            "probe_type": "iam_access_key_liveness",
            "resource": access_key_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "classification": "inconclusive",
            "compensating_control": "rate_limit_exceeded",
            "validation_tag": VALIDATION_TAG,
        }

    start = time.time()
    result = {
        "probe_type": "iam_access_key_liveness",
        "resource": access_key_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "classification": "inconclusive",
        "key_status": None,
        "last_used": None,
        "duration_ms": None,
        "compensating_control": None,
        "validation_tag": VALIDATION_TAG,
    }
    try:
        resp = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
        last_used_date = resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
        result["last_used"] = last_used_date.isoformat() if last_used_date else None

        user_name = resp.get("UserName")
        key_status = None
        if user_name:
            keys = iam_client.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
            match = next((k for k in keys if k["AccessKeyId"] == access_key_id), None)
            key_status = match["Status"] if match else None
        result["key_status"] = key_status

        if key_status == "Active" and last_used_date is not None:
            result["classification"] = "true_positive"
        elif key_status == "Inactive":
            result.update({"classification": "false_positive", "compensating_control": "key_status_inactive"})
        elif key_status == "Active" and last_used_date is None:
            result.update({"classification": "false_positive", "compensating_control": "key_active_but_never_used"})
    except Exception as e:
        result["compensating_control"] = f"probe_error:{str(e)[:80]}"
    result["duration_ms"] = round((time.time() - start) * 1000, 1)
    logger.info(
        "IAM key validation probe key=%s classification=%s duration_ms=%s tag=%s",
        access_key_id[:8] + "...",
        result["classification"],
        result["duration_ms"],
        VALIDATION_TAG,
    )
    return result
