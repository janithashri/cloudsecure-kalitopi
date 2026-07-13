import json
import logging
from datetime import timedelta

from django.utils import timezone

from api.models import ConfigChangeCursor
from .config import get_client

logger = logging.getLogger(__name__)


SUPPORTED_RESOURCE_TYPES = {
    "AWS::S3::Bucket",
    "AWS::EC2::Instance",
    "AWS::EC2::SecurityGroup",
    "AWS::IAM::Role",
    "AWS::IAM::User",
    "AWS::RDS::DBInstance",
    "AWS::KMS::Key",
    "AWS::CloudTrail::Trail",
}


def _normalize_config_resource(row: dict) -> tuple[str | None, str | None]:
    arn = row.get("arn") or row.get("ARN") or row.get("resourceArn")
    resource_type = row.get("resourceType")
    return arn, resource_type


def collect_changed_arns_from_config(
    account_id: str,
    role_name: str,
    region: str,
    lookback_minutes_default: int = 180,
) -> set[str]:
    """
    Return ARNs changed since last successful poll according to AWS Config advanced query.
    Non-fatal: returns empty set on any API/permission failure.
    """
    changed: set[str] = set()

    cursor, _ = ConfigChangeCursor.objects.get_or_create(
        account_id=account_id,
        region=region,
        defaults={"last_polled_at": timezone.now() - timedelta(minutes=lookback_minutes_default)},
    )
    since = cursor.last_polled_at or (timezone.now() - timedelta(minutes=lookback_minutes_default))
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Restrict to specific resource types we already support in fetchers/evaluator.
    quoted_types = ", ".join([f"'{x}'" for x in sorted(SUPPORTED_RESOURCE_TYPES)])
    expression = (
        "SELECT arn, resourceType, configurationItemCaptureTime "
        "WHERE resourceType IN ({types}) "
        "AND configurationItemCaptureTime > '{since}'"
    ).format(types=quoted_types, since=since_iso)

    try:
        cfg = get_client(account_id, role_name, "config", region)
        next_token = None
        while True:
            params = {"Expression": expression, "Limit": 100}
            if next_token:
                params["NextToken"] = next_token
            resp = cfg.select_resource_config(**params)
            for row in resp.get("Results") or []:
                try:
                    parsed = json.loads(row) if isinstance(row, str) else (row or {})
                except Exception:
                    continue
                arn, resource_type = _normalize_config_resource(parsed)
                if arn and resource_type in SUPPORTED_RESOURCE_TYPES:
                    changed.add(arn)

            next_token = resp.get("NextToken")
            if not next_token:
                break

        cursor.last_polled_at = timezone.now()
        cursor.save(update_fields=["last_polled_at", "updated_at"])
        logger.info(
            "AWS Config drift collector: account=%s region=%s changed_arns=%s since=%s",
            account_id,
            region,
            len(changed),
            since_iso,
        )
    except Exception as e:
        logger.warning("AWS Config drift collection failed for %s in %s: %s", account_id, region, e)

    return changed
