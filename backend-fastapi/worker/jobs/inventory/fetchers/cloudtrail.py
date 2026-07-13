from ..throttle import with_backoff


@with_backoff()
def fetch_cloudtrail_config(session, arn: str, region: str) -> dict:
    ct = session.client("cloudtrail", region_name=region)
    trail_name = arn.split("/")[-1]

    trails = ct.describe_trails(
        trailNameList=[trail_name], includeShadowTrails=False
    )
    if not trails["trailList"]:
        return {"arn": arn, "status": "not_found"}

    trail = trails["trailList"][0]
    status = ct.get_trail_status(Name=trail_name)

    try:
        selectors = ct.get_event_selectors(TrailName=trail_name)
        event_selectors = selectors.get("EventSelectors", [])
    except Exception:
        event_selectors = []

    return {
        "name": trail.get("Name"),
        "home_region": trail.get("HomeRegion"),
        "is_multi_region": trail.get("IsMultiRegionTrail"),
        "is_logging": status.get("IsLogging"),
        "log_validation_enabled": trail.get("LogFileValidationEnabled"),
        "s3_bucket": trail.get("S3BucketName"),
        "cloudwatch_logs_arn": trail.get("CloudWatchLogsLogGroupArn"),
        "kms_key_id": trail.get("KMSKeyId"),
        "event_selectors": event_selectors,
    }
