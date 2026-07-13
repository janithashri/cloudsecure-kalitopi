"""
Maps raw fetcher output to OPA input.asset format for each resource type.
"""
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

ASSET_TYPE_MAP = {
    # Resource Explorer (and current inventory pipeline) stores a simplified
    # type key like `ec2:security-group` / `iam:user`, not full CFN types.
    # Both forms must be present for correct OPA input building.
    "s3:bucket": "s3_bucket",
    "ec2:security-group": "security_group",
    "ec2:instance": "ec2_instance",
    "iam:user": "iam_user",
    "iam:role": "iam_role",
    "rds:db": "rds_instance",
    "kms:key": "kms_key",
    "cloudtrail:trail": "cloudtrail_trail",
    "AWS::IAM::Role": "iam_role",
    "AWS::IAM::User": "iam_user",
    "AWS::S3::Bucket": "s3_bucket",
    "AWS::EC2::Instance": "ec2_instance",
    "AWS::EC2::SecurityGroup": "security_group",
    "AWS::RDS::DBInstance": "rds_instance",
    "AWS::KMS::Key": "kms_key",
    "AWS::CloudTrail::Trail": "cloudtrail_trail",
}

# High-risk TCP ports (DB/management) from internet
HIGH_RISK_PORTS = {21, 22, 23, 25, 110, 143, 445, 1433, 1434, 1521, 2483, 3306, 3389, 5432, 5900, 6379, 7199, 8888, 9160, 9092, 11211, 27017, 27018}


def _normalize_tags(tags: dict | list) -> dict:
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    if isinstance(tags, list):
        return {t.get("Key", t.get("key", "")): t.get("Value", t.get("value", "")) for t in tags if isinstance(t, dict)}
    return {}


def _principal_aws_string(principal) -> str:
    if principal == "*":
        return "*"
    if isinstance(principal, dict):
        aws_p = principal.get("AWS")
        if isinstance(aws_p, str):
            return aws_p
        if isinstance(aws_p, list):
            return ",".join(str(p) for p in aws_p)
    return ""


def _parse_bucket_policy_statements(policy: dict | None) -> list[dict]:
    if not isinstance(policy, dict):
        return []
    statements = []
    for st in policy.get("Statement", []):
        if not isinstance(st, dict):
            continue
        action = st.get("Action", "")
        if isinstance(action, list):
            action = ",".join(str(a) for a in action)
        statements.append(
            {
                "effect": st.get("Effect", ""),
                "action": str(action),
                "principal_aws": _principal_aws_string(st.get("Principal")),
                "restricted_access_condition": bool(st.get("Condition")),
            }
        )
    return statements


def _normalize_acl_grants(raw_grants: list) -> list[dict]:
    normalized = []
    for g in raw_grants or []:
        if not isinstance(g, dict):
            continue
        grantee = g.get("grantee_uri") or g.get("grantee", "")
        normalized.append(
            {
                "grantee_uri": str(grantee),
                "permission": g.get("permission") or g.get("Permission", ""),
            }
        )
    return normalized


def _sensitive_data_tag(tags: dict) -> bool:
    classification = (
        tags.get("DataClassification")
        or tags.get("data_classification")
        or tags.get("data-classification")
        or ""
    ).lower()
    return classification in {"sensitive", "confidential", "pii"}


def _build_s3(config: dict, arn: str, region: str, account_id: str, tags: dict) -> dict:
    pab = config.get("public_access_block") or {}
    block_public_acls = pab.get("BlockPublicAcls") is True
    ignore_public_acls = pab.get("IgnorePublicAcls") is True
    block_public_policy = pab.get("BlockPublicPolicy") is True
    restrict_public_buckets = pab.get("RestrictPublicBuckets") is True
    block_fully = block_public_acls and ignore_public_acls and block_public_policy and restrict_public_buckets

    encryption = config.get("encryption")
    server_side_encryption_enabled = encryption is not None and len(encryption) > 0
    encryption_type = None
    if encryption and len(encryption) > 0:
        first = encryption[0] if isinstance(encryption[0], dict) else {}
        algo = first.get("SSEAlgorithm")
        if isinstance(algo, str):
            encryption_type = algo

    acl_grants = _normalize_acl_grants(config.get("acl_grants") or [])
    public_acl = any(
        "global/AllUsers" in g.get("grantee_uri", "")
        or "global/AuthenticatedUsers" in g.get("grantee_uri", "")
        for g in acl_grants
    )
    policy = config.get("policy")
    policy_status_public = config.get("policy_status_public")
    if policy_status_public is None:
        policy_status_public = False
        if isinstance(policy, dict):
            for st in policy.get("Statement", []):
                principal = st.get("Principal", {})
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    if st.get("Effect") != "Deny":
                        policy_status_public = True
                    break
    policy_public = policy_status_public is True
    bucket_policy_statements = _parse_bucket_policy_statements(policy)
    normalized_tags = _normalize_tags({**(tags or {}), **(config.get("tags") or {})})
    bpa_disabled = not block_fully
    exposure = "public_facing" if (policy_status_public or public_acl or bpa_disabled) else "internal"
    sensitive_data = _sensitive_data_tag(normalized_tags)
    secure_transport_policy = False
    if isinstance(policy, dict):
        for st in policy.get("Statement", []):
            if st.get("Effect") == "Deny":
                cond = st.get("Condition", {})
                if cond.get("Bool", {}).get("aws:SecureTransport") == "false":
                    secure_transport_policy = True
                    break

    has_cross_account = False
    if isinstance(policy, dict):
        for st in policy.get("Statement", []):
            principal = st.get("Principal", {})
            if principal == "*":
                has_cross_account = True
                break
            aws_principal = principal.get("AWS") if isinstance(principal, dict) else None
            if isinstance(aws_principal, str) and aws_principal != f"arn:aws:iam::{account_id}:root":
                has_cross_account = True
                break
            if isinstance(aws_principal, list):
                for p in aws_principal:
                    if p != "*" and account_id not in str(p):
                        has_cross_account = True
                        break

    versioning = config.get("versioning", "Disabled")
    versioning_enabled = versioning == "Enabled"
    mfa_delete = config.get("mfa_delete_enabled")
    if mfa_delete is None and isinstance(config.get("versioning_config"), dict):
        mfa_delete = config.get("versioning_config", {}).get("MfaDelete") == "Enabled"

    return {
        "asset_type": "s3_bucket",
        "type": "s3_bucket",
        "bucket_name": config.get("bucket_name", ""),
        "region": region,
        "account_id": account_id,
        "arn": arn,
        "block_public_acls": block_public_acls,
        "ignore_public_acls": ignore_public_acls,
        "block_public_policy": block_public_policy,
        "restrict_public_buckets": restrict_public_buckets,
        "public_access_block": {
            "block_public_acls": block_public_acls,
            "ignore_public_acls": ignore_public_acls,
            "block_public_policy": block_public_policy,
            "restrict_public_buckets": restrict_public_buckets,
        },
        "acl_grants": acl_grants,
        "policy_status_public": policy_status_public is True,
        "exposure": exposure,
        "sensitive_data": sensitive_data,
        "bucket_policy_statements": bucket_policy_statements,
        "is_public": not block_fully or public_acl or policy_public,
        "secure_transport_policy": secure_transport_policy,
        "versioning_enabled": versioning_enabled,
        "mfa_delete_enabled": mfa_delete,
        "access_logging_enabled": config.get("logging_enabled") is True,
        "server_side_encryption_enabled": server_side_encryption_enabled,
        "encryption_type": encryption_type or "",
        "has_cross_account_policy": has_cross_account,
        "tags": normalized_tags,
    }


def _build_iam_user(config: dict, arn: str, region: str, account_id: str, tags: dict) -> dict:
    name = config.get("name", "")
    inline = config.get("inline_policies") or {}
    has_console_password = config.get("password_last_used") and str(config.get("password_last_used")) != "Never"
    mfa_enabled = config.get("mfa_enabled") is True
    return {
        "asset_type": "iam_user",
        "user_name": name,
        "arn": arn,
        "region": region,
        "account_id": account_id,
        "has_console_password": has_console_password,
        "mfa_enabled": mfa_enabled,
        "inline_policy_names": list(inline.keys()) if isinstance(inline, dict) else [],
        "role_sensitive": False,
        "tags": _normalize_tags(config.get("tags", tags)),
    }


def _build_iam_role(config: dict, arn: str, region: str, account_id: str, tags: dict) -> dict:
    name = config.get("name", "")
    assume = config.get("assume_role_policy") or {}
    statements = assume.get("Statement", [])
    requires_mfa = False
    for st in statements:
        cond = st.get("Condition", {})
        if cond.get("Bool", {}).get("aws:MultiFactorAuthPresent") == "true":
            requires_mfa = True
            break
    principal_public = False
    for st in statements:
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal", {})
        if principal.get("AWS") == "*":
            principal_public = True
            break
        svc = principal.get("Service")
        if svc and "*" in str(svc):
            principal_public = True
            break
    role_sensitive = "admin" in name.lower() or "power" in name.lower() or "privilege" in name.lower()
    return {
        "asset_type": "iam_role",
        "role_name": name,
        "arn": arn,
        "region": region,
        "account_id": account_id,
        "requires_mfa": requires_mfa,
        "trust_policy_public_or_cross_account": principal_public,
        "role_sensitive": role_sensitive,
        "tags": _normalize_tags(config.get("tags", tags)),
    }


def _build_sg(config: dict, arn: str, region: str, account_id: str, tags: dict) -> dict:
    inbound = config.get("inbound_rules") or []
    allows_all_ingress = False
    allows_ssh = False
    allows_rdp = False
    allows_high_risk = False
    for r in inbound:
        proto = r.get("protocol")
        from_p = r.get("from_port")
        to_p = r.get("to_port")
        ipv4 = r.get("ipv4_ranges") or []
        ipv6 = r.get("ipv6_ranges") or []
        any_public = "0.0.0.0/0" in ipv4 or "::/0" in ipv6
        if not any_public:
            continue
        if proto in ("-1", -1) or (from_p in (0, None) and to_p in (65535, None)):
            allows_all_ingress = True
        if from_p == 22 and to_p == 22:
            allows_ssh = True
        if from_p == 3389 and to_p == 3389:
            allows_rdp = True
        if from_p is not None and to_p is not None and set(range(from_p, to_p + 1)) & HIGH_RISK_PORTS:
            allows_high_risk = True
        if from_p in HIGH_RISK_PORTS or to_p in HIGH_RISK_PORTS:
            allows_high_risk = True

    egress = config.get("outbound_rules") or []
    allows_all_egress = False
    for r in egress:
        ipv4 = r.get("ipv4_ranges") or []
        ipv6 = r.get("ipv6_ranges") or []
        if "0.0.0.0/0" in ipv4 or "::/0" in ipv6:
            allows_all_egress = True
            break

    return {
        "asset_type": "security_group",
        "group_id": config.get("group_id", ""),
        "group_name": config.get("group_name", ""),
        "region": region,
        "account_id": account_id,
        "arn": arn,
        "inbound_rules": inbound,
        "allows_all_ingress": allows_all_ingress,
        "allows_ssh": allows_ssh,
        "allows_rdp": allows_rdp,
        "allows_high_risk_ports": allows_high_risk,
        "allows_all_egress": allows_all_egress,
        "tags": _normalize_tags(config.get("tags", tags)),
    }


def _build_ec2(config: dict, arn: str, region: str, account_id: str, tags: dict) -> dict:
    meta = config.get("metadata_options") or {}
    imdsv2 = (meta.get("HttpTokens") or "").lower() == "required"
    has_public_ip = config.get("public_ip") is not None and config.get("public_ip") != ""
    iam_profile = config.get("iam_profile")
    return {
        "asset_type": "ec2_instance",
        "instance_id": config.get("instance_id", ""),
        "region": region,
        "account_id": account_id,
        "arn": arn,
        "has_public_ip": has_public_ip,
        "imdsv2_required": imdsv2,
        "iam_instance_profile_attached": bool(iam_profile),
        "tags": _normalize_tags(config.get("tags", tags)),
    }


def _build_rds(config: dict, arn: str, region: str, account_id: str, tags: dict) -> dict:
    vpc_sgs = config.get("vpc_security_groups") or []
    inside_vpc = len(vpc_sgs) > 0
    return {
        "asset_type": "rds_instance",
        "db_identifier": config.get("db_identifier", ""),
        "region": region,
        "account_id": account_id,
        "arn": arn,
        "publicly_accessible": config.get("publicly_accessible") is True,
        "storage_encrypted": config.get("storage_encrypted") is True,
        "multi_az": config.get("multi_az") is True,
        "deletion_protection": config.get("deletion_protection") is True,
        "backup_retention": config.get("backup_retention") or 0,
        "auto_minor_upgrade": config.get("auto_minor_upgrade") is True,
        "inside_vpc": inside_vpc,
        "tags": _normalize_tags(config.get("tags", tags)),
    }


def _build_kms(config: dict, arn: str, region: str, account_id: str, tags: dict) -> dict:
    policy = config.get("policy") or {}
    key_policy_public_or_external = False
    for st in policy.get("Statement", []):
        principal = st.get("Principal", {})
        if principal.get("AWS") == "*":
            key_policy_public_or_external = True
            break
        aws_p = principal.get("AWS")
        if isinstance(aws_p, list):
            for p in aws_p:
                if p == "*" or (isinstance(p, str) and account_id not in p and "root" not in p):
                    key_policy_public_or_external = True
                    break
        elif isinstance(aws_p, str) and "*" in aws_p and account_id not in aws_p:
            key_policy_public_or_external = True
            break

    key_arn = config.get("key_arn") or arn
    multi_region = "mrk-" in str(config.get("key_id", "")) or "multi" in str(key_arn).lower()
    return {
        "asset_type": "kms_key",
        "key_id": config.get("key_id", ""),
        "region": region,
        "account_id": account_id,
        "arn": arn,
        "key_manager": config.get("key_manager", "AWS"),
        "key_state": config.get("key_state", "Enabled"),
        "rotation_enabled": config.get("rotation_enabled") is True,
        "key_policy_public_or_external": key_policy_public_or_external,
        "multi_region": multi_region,
        "tags": _normalize_tags(config.get("tags", tags)),
    }


def _build_cloudtrail(config: dict, arn: str, region: str, account_id: str, tags: dict) -> dict:
    s3_bucket = config.get("s3_bucket") or ""
    return {
        "asset_type": "cloudtrail_trail",
        "name": config.get("name", ""),
        "region": region,
        "account_id": account_id,
        "arn": arn,
        "is_multi_region": config.get("is_multi_region") is True,
        "is_logging": config.get("is_logging") is True,
        "log_file_validation_enabled": config.get("log_validation_enabled") is True,
        "kms_encryption_enabled": bool(config.get("kms_key_id")),
        "s3_bucket": s3_bucket,
        "s3_bucket_public": config.get("s3_bucket_public") is True,
        "cloudwatch_logs_enabled": bool(config.get("cloudwatch_logs_arn")),
        "tags": _normalize_tags(config.get("tags", tags)),
    }


def build_opa_input(
    resource_type: str,
    arn: str,
    region: str,
    account_id: str,
    config: dict,
    tags: dict | None = None,
) -> dict:
    """
    Build the OPA input.asset object from fetcher config.
    Returns {"input": {"asset": {...}}} for OPA POST body.
    """
    tags = tags or {}
    asset_type = ASSET_TYPE_MAP.get(resource_type)
    if not asset_type:
        logger.warning("Unknown resource_type for rule engine: %s", resource_type)
        return {"input": {"asset": {"asset_type": "unknown", "arn": arn, "region": region}}}

    build = {
        "s3_bucket": _build_s3,
        "iam_user": _build_iam_user,
        "iam_role": _build_iam_role,
        "security_group": _build_sg,
        "ec2_instance": _build_ec2,
        "rds_instance": _build_rds,
        "kms_key": _build_kms,
        "cloudtrail_trail": _build_cloudtrail,
    }.get(asset_type)
    if not build:
        return {"input": {"asset": {"asset_type": asset_type, "arn": arn, "region": region}}}

    asset = build(config, arn, region, account_id, tags)
    return {"input": {"asset": asset}}
