import json
import logging

from botocore.exceptions import ClientError
from ..throttle import with_backoff

logger = logging.getLogger(__name__)


@with_backoff()
def fetch_s3_config(session, arn: str, region: str) -> dict:
    bucket_name = arn.split(":::")[-1]
    s3 = session.client("s3", region_name="us-east-1")
    config = {"bucket_name": bucket_name}

    try:
        r = s3.get_public_access_block(Bucket=bucket_name)
        config["public_access_block"] = r.get("PublicAccessBlockConfiguration", {})
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "NoSuchPublicAccessBlockConfiguration":
            config["public_access_block"] = None
        else:
            logger.warning("S3 get_public_access_block failed for %s: %s", bucket_name, e)
            config["public_access_block"] = None

    try:
        r = s3.get_bucket_policy(Bucket=bucket_name)
        config["policy"] = json.loads(r["Policy"])
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "NoSuchBucketPolicy":
            config["policy"] = None
        else:
            logger.warning("S3 get_bucket_policy failed for %s: %s", bucket_name, e)
            config["policy"] = None

    try:
        r = s3.get_bucket_policy_status(Bucket=bucket_name)
        config["policy_status_public"] = r.get("PolicyStatus", {}).get("IsPublic") is True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code not in ("NoSuchBucketPolicy", "NoSuchBucket"):
            logger.warning("S3 get_bucket_policy_status failed for %s: %s", bucket_name, e)
        config["policy_status_public"] = False

    try:
        r = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = r["ServerSideEncryptionConfiguration"]["Rules"]
        config["encryption"] = [
            rule["ApplyServerSideEncryptionByDefault"] for rule in rules
        ]
    except Exception:
        config["encryption"] = None

    try:
        r = s3.get_bucket_versioning(Bucket=bucket_name)
        config["versioning"] = r.get("Status", "Disabled")
    except Exception as e:
        logger.warning("S3 get_bucket_versioning failed for %s: %s", bucket_name, e)
        config["versioning"] = "Disabled"

    try:
        r = s3.get_bucket_logging(Bucket=bucket_name)
        config["logging_enabled"] = "LoggingEnabled" in r
    except Exception as e:
        logger.warning("S3 get_bucket_logging failed for %s: %s", bucket_name, e)
        config["logging_enabled"] = False

    try:
        r = s3.get_bucket_acl(Bucket=bucket_name)
        config["acl_grants"] = [
            {
                "grantee": g["Grantee"].get("URI", g["Grantee"].get("ID", "")),
                "permission": g["Permission"],
            }
            for g in r.get("Grants", [])
        ]
    except Exception as e:
        logger.warning("S3 get_bucket_acl failed for %s: %s", bucket_name, e)
        config["acl_grants"] = []

    try:
        r = s3.get_bucket_tagging(Bucket=bucket_name)
        config["tags"] = {
            t["Key"]: t["Value"] for t in r.get("TagSet", []) if isinstance(t, dict) and "Key" in t
        }
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code != "NoSuchTagSet":
            logger.warning("S3 get_bucket_tagging failed for %s: %s", bucket_name, e)
        config["tags"] = {}

    return config
