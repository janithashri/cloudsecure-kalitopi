"""
Evaluate a single resource against all applicable Rego packages; create/update Finding records.
"""
import logging
import re

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.db import repositories as repo
from app.db.repositories import utcnow
from app.models.orm import InventoryRun

from .active_validator import reset_probe_state, validate_iam_key_exposure, validate_s3_exposure
from .input_builder import build_opa_input
from .opa_client import evaluate, load_policy

logger = logging.getLogger(__name__)

S3_BASE_PACKAGES = ["cloudsecure.rules.cis_aws_s3", "cloudsecure.rules.india_aws_s3"]
CONSOLIDATED_S3_PACKAGE = "cloudsecure.rules.consolidated_s3"

SUPPRESSED_S3_PUBLIC_RULE_IDS = {
    "CIS-2.1.4",
    "CIS-2.1.4-PUBLIC",
    "CIS-2.1-CROSS-ACCOUNT",
    "DPDP-S3-PUBLIC",
    "DPDP-S3-IS-PUBLIC",
    "RBI-S3-CROSS-ACCOUNT",
}

IAM_KEY_VALIDATION_RULE_PREFIXES = ("CIS-1.", "CERT-In-IAM-")

PACKAGE_MAP = {
    "s3:bucket": S3_BASE_PACKAGES,
    "ec2:security-group": ["cloudsecure.rules.cis_aws_ec2", "cloudsecure.rules.india_aws_ec2"],
    "ec2:instance": ["cloudsecure.rules.cis_aws_ec2", "cloudsecure.rules.india_aws_ec2"],
    "iam:user": ["cloudsecure.rules.cis_aws_iam", "cloudsecure.rules.india_aws_iam"],
    "iam:role": ["cloudsecure.rules.cis_aws_iam", "cloudsecure.rules.india_aws_iam"],
    "rds:db": ["cloudsecure.rules.cis_aws_rds", "cloudsecure.rules.india_aws_rds"],
    "kms:key": ["cloudsecure.rules.cis_aws_kms", "cloudsecure.rules.india_aws_kms"],
    "cloudtrail:trail": [
        "cloudsecure.rules.cis_aws_cloudtrail",
        "cloudsecure.rules.india_aws_cloudtrail",
    ],
    "AWS::S3::Bucket": S3_BASE_PACKAGES,
    "AWS::EC2::SecurityGroup": ["cloudsecure.rules.cis_aws_ec2", "cloudsecure.rules.india_aws_ec2"],
    "AWS::EC2::Instance": ["cloudsecure.rules.cis_aws_ec2", "cloudsecure.rules.india_aws_ec2"],
    "AWS::IAM::Role": ["cloudsecure.rules.cis_aws_iam", "cloudsecure.rules.india_aws_iam"],
    "AWS::IAM::User": ["cloudsecure.rules.cis_aws_iam", "cloudsecure.rules.india_aws_iam"],
    "AWS::RDS::DBInstance": ["cloudsecure.rules.cis_aws_rds", "cloudsecure.rules.india_aws_rds"],
    "AWS::KMS::Key": ["cloudsecure.rules.cis_aws_kms", "cloudsecure.rules.india_aws_kms"],
    "AWS::CloudTrail::Trail": [
        "cloudsecure.rules.cis_aws_cloudtrail",
        "cloudsecure.rules.india_aws_cloudtrail",
    ],
}


def _extract_package_path(rego_policy: str) -> str | None:
    if not isinstance(rego_policy, str):
        return None
    match = re.search(r"^\s*package\s+([A-Za-z0-9_.]+)\s*$", rego_policy, flags=re.MULTILINE)
    if not match:
        return None
    return match.group(1).replace(".", "/")


def _s3_packages() -> list[str]:
    settings = get_settings()
    if settings.consolidated_s3_rules_enabled:
        return S3_BASE_PACKAGES + [CONSOLIDATED_S3_PACKAGE]
    return S3_BASE_PACKAGES


def _packages_for_resource(resource_type: str) -> list[str] | None:
    if resource_type in ("s3:bucket", "AWS::S3::Bucket"):
        return _s3_packages()
    return PACKAGE_MAP.get(resource_type)


def _should_suppress_s3_rule(rule_id: str) -> bool:
    settings = get_settings()
    return settings.suppress_fragmented_s3_public_rules and rule_id in SUPPRESSED_S3_PUBLIC_RULE_IDS


def _needs_iam_key_validation(rule_id: str, msg: dict) -> bool:
    if msg.get("access_key_id"):
        return True
    if not rule_id.startswith(IAM_KEY_VALIDATION_RULE_PREFIXES):
        return False
    return "key" in rule_id.lower() or "access" in rule_id.lower()


def _apply_validation_probe(
    msg: dict,
    rule_id: str,
    resource_type: str,
    region: str,
    config: dict,
    iam_client=None,
) -> tuple[str, dict]:
    """Run active behavioral validation; return (status, enriched_msg)."""
    enriched = dict(msg)
    status = "OPEN"

    if rule_id == "CONSOLIDATED-S3-001" and resource_type in ("s3:bucket", "AWS::S3::Bucket"):
        bucket_name = config.get("bucket_name") or msg.get("bucket_name", "")
        if bucket_name:
            probe = validate_s3_exposure(bucket_name, region or "us-east-1")
            enriched["validation_probe"] = probe
            if probe["classification"] == "false_positive":
                status = "COMPENSATING_CONTROL_DETECTED"
            return status, enriched

    if _needs_iam_key_validation(rule_id, msg) and iam_client is not None:
        access_key_id = msg.get("access_key_id")
        if access_key_id:
            probe = validate_iam_key_exposure(access_key_id, iam_client)
            enriched["validation_probe"] = probe
            if probe["classification"] == "false_positive":
                status = "COMPENSATING_CONTROL_DETECTED"
            return status, enriched

    return status, enriched


def _evaluate_custom_rules(db, resource_type: str, provider_id: int, tenant_id: int, opa_input: dict) -> list[dict]:
    denials: list[dict] = []
    rules = repo.get_enabled_custom_rules(db, tenant_id, resource_type, provider_id)
    for rule in rules:
        if rule.provider_id is not None and rule.provider_id != provider_id:
            continue
        package_path = _extract_package_path(rule.rego_policy)
        if not package_path:
            logger.warning("Custom rule %s skipped: missing package declaration", rule.rule_id)
            continue
        policy_id = f"custom_{tenant_id}_{rule.id}"
        if not load_policy(policy_id, rule.rego_policy):
            logger.warning("Custom rule %s skipped: failed to load policy", rule.rule_id)
            continue
        hits = evaluate(package_path, opa_input)
        for msg in hits:
            if not isinstance(msg, dict):
                continue
            merged = dict(msg)
            merged["rule_id"] = merged.get("rule_id") or rule.rule_id
            merged["issue"] = merged.get("issue") or rule.description or rule.name
            merged["severity"] = merged.get("severity") or rule.severity
            if not isinstance(merged.get("compliance"), list) or not merged.get("compliance"):
                merged["compliance"] = rule.compliance_frameworks or []
            merged["remediation"] = merged.get("remediation") or rule.description or ""
            denials.append(merged)
    return denials


def evaluate_resource(
    resource_type: str,
    arn: str,
    account_id: str,
    region: str,
    config: dict,
    tags: dict,
    inventory_run_id: int,
    tenant_id: int,
    provider_id: int,
    iam_client=None,
) -> int:
    packages = _packages_for_resource(resource_type)
    if not packages:
        return 0

    try:
        opa_input = build_opa_input(resource_type, arn, region, account_id, config, tags)
    except Exception as e:
        logger.warning("input_builder failed for %s %s: %s", resource_type, arn[:80], e)
        return 0

    all_denials = []
    for pkg in packages:
        pkg_path = pkg.replace(".", "/")
        denials = evaluate(pkg_path, opa_input)
        for msg in denials:
            if not isinstance(msg, dict):
                continue
            rule_id = msg.get("rule_id") or "unknown"
            if _should_suppress_s3_rule(rule_id):
                continue
            all_denials.append(msg)

    with SessionLocal() as db:
        all_denials.extend(
            _evaluate_custom_rules(db, resource_type, provider_id, tenant_id, opa_input)
        )
        created = 0
        validation_cache: dict[str, tuple[str, dict]] = {}
        for msg in all_denials:
            if not isinstance(msg, dict):
                continue
            rule_id = msg.get("rule_id") or "unknown"
            rule_name = msg.get("issue", "")[:255]
            severity = msg.get("severity", "MEDIUM")
            compliance = msg.get("compliance")
            if not isinstance(compliance, list):
                compliance = []
            remediation = msg.get("remediation", "")

            if rule_id in validation_cache:
                status, cached_msg = validation_cache[rule_id]
                enriched = dict(msg)
                if cached_msg.get("validation_probe"):
                    enriched["validation_probe"] = cached_msg["validation_probe"]
                msg = enriched
            else:
                status, msg = _apply_validation_probe(msg, rule_id, resource_type, region, config, iam_client)
                validation_cache[rule_id] = (status, msg)

            existing = repo.finding_exists(db, arn, rule_id)
            if existing:
                updates = {
                    "last_seen": utcnow(),
                    "inventory_run_id": inventory_run_id,
                }
                if existing.status != "SUPPRESSED":
                    new_probe = msg.get("validation_probe") if isinstance(msg.get("validation_probe"), dict) else {}
                    old_probe = (
                        (existing.raw_finding or {}).get("validation_probe")
                        if isinstance(existing.raw_finding, dict)
                        else {}
                    )
                    if (
                        new_probe.get("classification") == "inconclusive"
                        and old_probe.get("classification") in ("true_positive", "false_positive")
                    ):
                        msg = dict(msg)
                        msg["validation_probe"] = old_probe
                        if old_probe.get("classification") == "false_positive":
                            status = "COMPENSATING_CONTROL_DETECTED"
                        elif old_probe.get("classification") == "true_positive":
                            status = "OPEN"
                    updates.update(
                        raw_finding=msg,
                        remediation_steps=remediation,
                        compliance_frameworks=compliance,
                        severity=severity,
                        status=status,
                    )
                repo.update_finding(db, existing, **updates)
                continue

            repo.create_finding(
                db,
                tenant_id=tenant_id,
                provider_id=provider_id,
                inventory_run_id=inventory_run_id,
                arn=arn,
                account_id=account_id,
                resource_type=resource_type,
                region=region,
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity,
                status=status,
                compliance_frameworks=compliance,
                remediation_steps=remediation,
                raw_finding=msg,
                first_seen=utcnow(),
                last_seen=utcnow(),
            )
            created += 1
    return created


def run_rule_engine_for_inventory_run(inventory_run_id: int) -> int:
    reset_probe_state()
    with SessionLocal() as db:
        run = db.get(InventoryRun, inventory_run_id)
        if not run:
            logger.warning("InventoryRun %s not found", inventory_run_id)
            return 0
        provider = repo.get_provider(db, run.provider_id)
        if not provider:
            return 0
        account_id = provider.aws_account_id
        configs = repo.list_resource_configs_for_account(db, account_id)

    total_created = 0
    for rc in configs:
        try:
            n = evaluate_resource(
                resource_type=rc.resource_type,
                arn=rc.arn,
                account_id=rc.account_id,
                region=rc.region,
                config=rc.config,
                tags=rc.tags or {},
                inventory_run_id=run.id,
                tenant_id=run.tenant_id,
                provider_id=run.provider_id,
            )
            total_created += n
        except Exception as e:
            logger.warning("evaluate_resource failed for %s: %s", rc.arn[:80], e)
    return total_created
