"""
Evaluate a single resource against all applicable Rego packages; create/update Finding records.
"""
import logging
import re

from django.db.models import Q
from django.utils import timezone

from api.models import CustomRule, Finding, InventoryRun, ResourceConfig
from .input_builder import build_opa_input
from .opa_client import evaluate, load_policy

logger = logging.getLogger(__name__)

PACKAGE_MAP = {
    # Resource Explorer (and current inventory pipeline) stores simplified
    # type keys like `ec2:security-group` / `iam:user` rather than CFN types.
    # Both forms must be present so evaluation works regardless of which type
    # string the inventory pipeline passes.
    "s3:bucket": [
        "cloudsecure.rules.cis_aws_s3",
        "cloudsecure.rules.india_aws_s3",
    ],
    "ec2:security-group": [
        "cloudsecure.rules.cis_aws_ec2",
        "cloudsecure.rules.india_aws_ec2",
    ],
    "ec2:instance": [
        "cloudsecure.rules.cis_aws_ec2",
        "cloudsecure.rules.india_aws_ec2",
    ],
    "iam:user": [
        "cloudsecure.rules.cis_aws_iam",
        "cloudsecure.rules.india_aws_iam",
    ],
    "iam:role": [
        "cloudsecure.rules.cis_aws_iam",
        "cloudsecure.rules.india_aws_iam",
    ],
    "rds:db": [
        "cloudsecure.rules.cis_aws_rds",
        "cloudsecure.rules.india_aws_rds",
    ],
    "kms:key": [
        "cloudsecure.rules.cis_aws_kms",
        "cloudsecure.rules.india_aws_kms",
    ],
    "cloudtrail:trail": [
        "cloudsecure.rules.cis_aws_cloudtrail",
        "cloudsecure.rules.india_aws_cloudtrail",
    ],
    "AWS::S3::Bucket": [
        "cloudsecure.rules.cis_aws_s3",
        "cloudsecure.rules.india_aws_s3",
    ],
    "AWS::EC2::SecurityGroup": [
        "cloudsecure.rules.cis_aws_ec2",
        "cloudsecure.rules.india_aws_ec2",
    ],
    "AWS::EC2::Instance": [
        "cloudsecure.rules.cis_aws_ec2",
        "cloudsecure.rules.india_aws_ec2",
    ],
    "AWS::IAM::Role": [
        "cloudsecure.rules.cis_aws_iam",
        "cloudsecure.rules.india_aws_iam",
    ],
    "AWS::IAM::User": [
        "cloudsecure.rules.cis_aws_iam",
        "cloudsecure.rules.india_aws_iam",
    ],
    "AWS::RDS::DBInstance": [
        "cloudsecure.rules.cis_aws_rds",
        "cloudsecure.rules.india_aws_rds",
    ],
    "AWS::KMS::Key": [
        "cloudsecure.rules.cis_aws_kms",
        "cloudsecure.rules.india_aws_kms",
    ],
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


def _evaluate_custom_rules(
    resource_type: str,
    provider_id: int,
    tenant_id: int,
    opa_input: dict,
) -> list[dict]:
    denials: list[dict] = []
    rules = CustomRule.objects.filter(
        tenant_id=tenant_id,
        enabled=True,
        resource_type=resource_type,
    ).filter(Q(provider_id=provider_id) | Q(provider__isnull=True))

    for rule in rules:
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
    inventory_run: InventoryRun,
    tenant_id: int,
    provider_id: int,
) -> int:
    """
    Build OPA input, evaluate each package for this resource type, and upsert Finding rows.
    Never changes status on existing findings (preserve SUPPRESSED). Updates last_seen and inventory_run.
    Returns count of new findings created (or total violations if you prefer; spec said "count of new findings created").
    """
    packages = PACKAGE_MAP.get(resource_type)
    if not packages:
        return 0

    try:
        opa_input = build_opa_input(resource_type, arn, region, account_id, config, tags)
    except Exception as e:
        logger.warning("input_builder failed for %s %s: %s", resource_type, arn[:80], e)
        return 0

    all_denials = []
    for pkg in packages:
        # OPA data path uses dots: cloudsecure.rules.cis_aws_s3
        pkg_path = pkg.replace(".", "/")
        denials = evaluate(pkg_path, opa_input)
        all_denials.extend(denials)
    all_denials.extend(
        _evaluate_custom_rules(
            resource_type=resource_type,
            provider_id=provider_id,
            tenant_id=tenant_id,
            opa_input=opa_input,
        )
    )

    created = 0
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

        existing = Finding.objects.filter(arn=arn, rule_id=rule_id).first()
        if existing:
            existing.last_seen = timezone.now()
            existing.inventory_run = inventory_run
            update_fields = ["last_seen", "inventory_run"]
            if existing.status != "SUPPRESSED":
                existing.raw_finding = msg
                existing.remediation_steps = remediation
                existing.compliance_frameworks = compliance
                existing.severity = severity
                update_fields.extend(["raw_finding", "remediation_steps", "compliance_frameworks", "severity"])
            existing.save(update_fields=update_fields)
            continue

        Finding.objects.create(
            tenant_id=tenant_id,
            provider_id=provider_id,
            inventory_run=inventory_run,
            arn=arn,
            account_id=account_id,
            resource_type=resource_type,
            region=region,
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            status="OPEN",
            compliance_frameworks=compliance,
            remediation_steps=remediation,
            raw_finding=msg,
        )
        created += 1

    return created


def run_rule_engine_for_inventory_run(inventory_run_id: int) -> int:
    """
    For a given InventoryRun, load ResourceConfig rows for the same account/run context,
    evaluate each resource, and return total new findings created.
    """
    try:
        run = InventoryRun.objects.get(pk=inventory_run_id)
    except InventoryRun.DoesNotExist:
        logger.warning("InventoryRun %s not found", inventory_run_id)
        return 0

    tenant_id = run.tenant_id
    provider_id = run.provider_id
    provider = run.provider
    account_id = getattr(provider, "aws_account_id", None) or run.stats.get("account_id")
    if not account_id:
        logger.warning("No account_id for InventoryRun %s", inventory_run_id)
        return 0
    configs = ResourceConfig.objects.filter(account_id=account_id)

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
                inventory_run=run,
                tenant_id=tenant_id,
                provider_id=provider_id,
            )
            total_created += n
        except Exception as e:
            logger.warning("evaluate_resource failed for %s: %s", rc.arn[:80], e)
    return total_created
