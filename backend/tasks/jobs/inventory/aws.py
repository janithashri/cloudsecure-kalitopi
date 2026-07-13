import logging
import os
import time

from django.utils import timezone

from api.models import ResourceConfig
from .config import get_client, get_session
from .config_drift import collect_changed_arns_from_config
from .fetchers import FETCHER_MAP
from .hashing import compute_config_hash, compute_tag_hash
from .neo4j_writer import get_neo4j_driver, tombstone_resource, write_resource_to_neo4j
from .state import load_hashes, save_hashes
from .throttle import stagger_accounts, with_backoff

logger = logging.getLogger(__name__)

AGGREGATOR_REGION = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")


def _arn_to_cfn_type(arn: str) -> str | None:
    """
    Derive a CloudFormation-style type from ARN for FETCHER_MAP lookup.
    e.g. arn:aws:ec2:region:account:security-group/sg-xxx -> AWS::EC2::SecurityGroup
    """
    parts = arn.split(":")
    if len(parts) < 6:
        return None
    service = (parts[2] or "").strip().upper()
    resource_part = (parts[5] or "").split("/")[0].strip().lower()
    if not service or not resource_part:
        return None

    # Service-specific canonical mappings for common ARN resource tokens.
    if service == "S3":
        return "AWS::S3::Bucket"
    if service == "IAM":
        if resource_part == "role":
            return "AWS::IAM::Role"
        if resource_part == "user":
            return "AWS::IAM::User"
    if service == "RDS":
        if resource_part == "db":
            return "AWS::RDS::DBInstance"
    if service == "KMS":
        if resource_part == "key":
            return "AWS::KMS::Key"
    if service == "CLOUDTRAIL":
        if resource_part == "trail":
            return "AWS::CloudTrail::Trail"

    # Generic fallback: security-group -> SecurityGroup, instance -> Instance
    pascal = "".join(w.capitalize() for w in resource_part.replace("_", "-").split("-"))
    return f"AWS::{service}::{pascal}"


def _get_fetcher(resource_type: str, arn: str):
    """Return (fetcher, effective_resource_type)."""
    fetcher = FETCHER_MAP.get(resource_type)
    if fetcher is not None:
        return fetcher, resource_type
    cfn_type = _arn_to_cfn_type(arn)
    if cfn_type:
        fetcher = FETCHER_MAP.get(cfn_type)
        if fetcher is not None:
            logger.info("Resolved fetcher via ARN: %r -> %s", arn[:80], cfn_type)
            return fetcher, cfn_type
    return None, resource_type


class ConfigurationError(RuntimeError):
    pass


def get_resource_explorer_view_arn(account_id: str, role_name: str) -> str:
    """Return the default view ARN for Resource Explorer (required for search())."""
    client = get_client(account_id, role_name, "resource-explorer-2", AGGREGATOR_REGION)
    try:
        index = client.get_index()
        if index.get("Type") != "AGGREGATOR":
            raise ConfigurationError(
                f"Account {account_id}: Resource Explorer index exists but is LOCAL, not AGGREGATOR."
                " Run: aws resource-explorer-2 create-index --type AGGREGATOR"
            )
    except client.exceptions.ResourceNotFoundException:
        raise ConfigurationError(
            f"Account {account_id}: Resource Explorer index not found."
            " Enable it: aws resource-explorer-2 create-index --type AGGREGATOR"
        )
    try:
        default_view = client.get_default_view()
        view_arn = default_view.get("ViewArn")
        if not view_arn:
            raise ConfigurationError(
                f"Account {account_id}: No default view for Resource Explorer."
                " Associate a default view in the AWS console or run: aws resource-explorer-2 associate-default-view --view-arn <ViewArn>"
            )
        return view_arn
    except client.exceptions.ResourceNotFoundException:
        raise ConfigurationError(
            f"Account {account_id}: Resource Explorer has no default view."
            " Create a view and set it as default in the AWS console."
        )
    except client.exceptions.AccessDeniedException:
        # Fallback: if GetDefaultView is not allowed, try ListViews and use the first view
        try:
            response = client.list_views()
            views = response.get("Views") or []
            if not views:
                raise ConfigurationError(
                    f"Account {account_id}: Resource Explorer has no views and GetDefaultView is not allowed."
                    " Add resource-explorer-2:GetDefaultView to CloudSecureRole, or create a view."
                )
            view_arn = views[0].get("ViewArn") if isinstance(views[0], dict) else getattr(views[0], "ViewArn", None)
            if view_arn:
                return view_arn
        except client.exceptions.AccessDeniedException:
            pass
        raise ConfigurationError(
            f"Account {account_id}: IAM role must allow resource-explorer-2:GetDefaultView or resource-explorer-2:ListViews."
            " Add one of these actions to the policy attached to CloudSecureRole."
        )


@with_backoff(max_attempts=5)
def search_resources_page(
    client,
    view_arn: str,
    query: str,
    resource_types: list,
    next_token: str | None = None,
) -> dict:
    params = {
        "ViewArn": view_arn,
        "QueryString": query,
        "MaxResults": 100,
    }
    if next_token:
        params["NextToken"] = next_token
    return client.search(**params)


def _extract_tags(resource: dict) -> dict:
    """
    Resource Explorer returns Properties with tags in varying shapes.
    We normalize into {key: value}.
    """
    props = resource.get("Properties") or []
    tags = {}
    for p in props:
        if not isinstance(p, dict):
            continue
        if p.get("Name") != "tags":
            continue
        value = p.get("Value") or []
        if isinstance(value, list):
            for t in value:
                if not isinstance(t, dict):
                    continue
                k = t.get("Key")
                v = t.get("Value")
                if k is not None:
                    tags[str(k)] = "" if v is None else str(v)
        elif isinstance(value, dict):
            # Some SDKs may return tags as dict already.
            for k, v in value.items():
                tags[str(k)] = "" if v is None else str(v)
    return tags


def poll_resource_explorer(account_id: str, role_name: str) -> dict:
    """
    Returns {arn: {'tag_hash': str, 'type': str, 'region': str, 'tags': dict}}
    """
    client = get_client(account_id, role_name, "resource-explorer-2", AGGREGATOR_REGION)
    view_arn = get_resource_explorer_view_arn(account_id, role_name)
    results: dict[str, dict] = {}
    next_token = None
    page = 0

    while True:
        page += 1
        response = search_resources_page(client, view_arn, "", [], next_token)

        for resource in response.get("Resources", []):
            arn = resource.get("Arn")
            if not arn:
                continue
            resource_type = resource.get("ResourceType", "unknown")
            region = resource.get("Region", "global")
            tags = _extract_tags(resource)
            results[arn] = {
                "tag_hash": compute_tag_hash(arn, resource_type, region, tags),
                "type": resource_type,
                "region": region,
                "tags": tags,
            }

        next_token = response.get("NextToken")
        if not next_token:
            break
        time.sleep(0.1)

    logger.info("Account %s: found %s resources in %s pages", account_id, len(results), page)
    return results


def _poll_s3_buckets(account_id: str, role_name: str) -> dict:
    """
    Fallback S3 discovery.
    Resource Explorer may not always surface S3 buckets promptly; list buckets
    directly so inventory/rule engine can evaluate S3 controls.
    Returns same shape as poll_resource_explorer().
    """
    out: dict[str, dict] = {}
    try:
        s3 = get_client(account_id, role_name, "s3", "us-east-1")
        resp = s3.list_buckets()
        for b in (resp.get("Buckets") or []):
            name = b.get("Name")
            if not name:
                continue
            arn = f"arn:aws:s3:::{name}"

            region = "us-east-1"
            try:
                loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
                # AWS returns None for us-east-1
                region = loc or "us-east-1"
            except Exception:
                pass

            tags = {}
            try:
                tagging = s3.get_bucket_tagging(Bucket=name)
                for t in tagging.get("TagSet") or []:
                    k = t.get("Key")
                    v = t.get("Value")
                    if k is not None:
                        tags[str(k)] = "" if v is None else str(v)
            except Exception:
                # No tags/denied is non-fatal for discovery.
                tags = {}

            resource_type = "AWS::S3::Bucket"
            out[arn] = {
                "tag_hash": compute_tag_hash(arn, resource_type, region, tags),
                "type": resource_type,
                "region": region,
                "tags": tags,
            }
    except Exception as e:
        logger.warning("S3 bucket discovery fallback failed for %s: %s", account_id, e)
    return out


def compute_delta(current_arns: dict, previous_hashes: dict) -> dict:
    current_set = set(current_arns.keys())
    previous_set = set(previous_hashes.keys())

    new_arns = current_set - previous_set
    changed_arns = {
        arn
        for arn in (current_set & previous_set)
        if current_arns[arn]["tag_hash"] != previous_hashes[arn].get("tag_hash")
    }
    deleted_arns = previous_set - current_set

    return {
        "new": new_arns,
        "changed": changed_arns,
        "deleted": deleted_arns,
    }


def has_config_drifted(arn: str, new_config: dict, previous_hashes: dict) -> tuple[bool, str]:
    new_hash = compute_config_hash(arn, new_config)
    old_hash = previous_hashes.get(arn, {}).get("config_hash")
    return new_hash != old_hash, new_hash


def run_inventory_pull(tenant_id: int, provider_id: int, run) -> dict:
    from providers.models import Provider
    from accounts.models import Tenant

    tenant = Tenant.objects.get(id=tenant_id)
    provider = Provider.objects.get(id=provider_id)
    account_id = provider.aws_account_id
    role_name = provider.inventory_role_name

    stats = {
        "total": 0,
        "delta_count": 0,
        "config_drifted": 0,
        "new": 0,
        "changed": 0,
        "deleted": 0,
        "new_findings": 0,
        "successfully_fetched": 0,
        "fetch_failed": 0,
        "skipped_no_fetcher": 0,
        "api_calls_made": 0,
    }

    neo4j_driver = get_neo4j_driver()

    class _Account:
        def __init__(self, aws_account_id: str):
            self.aws_account_id = aws_account_id

    accounts = [_Account(account_id)]

    for batch in stagger_accounts(accounts, batch_size=10, delay_seconds=180):
        for account in batch:
            _process_account(account, role_name, neo4j_driver, stats, tenant, provider, run)

    return stats


def _process_account(account, role_name, neo4j_driver, stats, tenant, provider, run):
    from django.conf import settings

    account_id = account.aws_account_id
    logger.info("Processing account %s", account_id)

    current_arns = poll_resource_explorer(account_id, role_name)
    # Optional (disabled by default): direct S3 discovery fallback.
    # Enable only when troubleshooting RE indexing gaps.
    if getattr(settings, "ENABLE_S3_FALLBACK_DISCOVERY", False):
        for arn, meta in _poll_s3_buckets(account_id, role_name).items():
            current_arns[arn] = meta
    stats["total"] += len(current_arns)

    previous_hashes = load_hashes(account_id)

    delta = compute_delta(current_arns, previous_hashes)
    delta_arns = delta["new"] | delta["changed"]

    # Optional: augment delta with AWS Config-detected config changes.
    # This fills the gap where Resource Explorer may not reflect non-tag config drift.
    config_changed_arns = set()
    if getattr(settings, "ENABLE_AWS_CONFIG_DRIFT", False):
        cfg_region = getattr(settings, "AWS_CONFIG_REGION", AGGREGATOR_REGION) or AGGREGATOR_REGION
        config_changed_arns = collect_changed_arns_from_config(
            account_id=account_id,
            role_name=role_name,
            region=cfg_region,
            lookback_minutes_default=getattr(settings, "AWS_CONFIG_INITIAL_LOOKBACK_MINUTES", 180),
        )
        # Only evaluate ARNs we can currently discover/resolve in this run.
        config_changed_arns = {arn for arn in config_changed_arns if arn in current_arns}
        if config_changed_arns:
            logger.info("AWS Config drift detected %s changed ARNs", len(config_changed_arns))
        stats["config_changed_signals"] = stats.get("config_changed_signals", 0) + len(config_changed_arns)
        delta_arns |= config_changed_arns

    stats["delta_count"] += len(delta_arns)
    stats["new"] += len(delta["new"])
    stats["changed"] += len(delta["changed"])
    stats["deleted"] += len(delta["deleted"])

    new_hashes = dict(previous_hashes)

    # One global session creation ensures STS is available; per-resource uses regional session.
    get_session(account_id, role_name, "us-east-1")

    seen_skipped_types = set()
    for arn in delta_arns:
        resource_meta = current_arns[arn]
        resource_type = resource_meta["type"]
        region = resource_meta["region"]
        fetcher, effective_resource_type = _get_fetcher(resource_type, arn)

        if not fetcher:
            stats["skipped_no_fetcher"] += 1
            cfn_type = _arn_to_cfn_type(arn)
            if resource_type not in seen_skipped_types:
                seen_skipped_types.add(resource_type)
                logger.info(
                    "No fetcher for resource_type=%r (also tried ARN-derived %r); FETCHER_MAP keys: %s",
                    resource_type,
                    cfn_type,
                    list(FETCHER_MAP.keys()),
                )
            new_hashes[arn] = {
                "tag_hash": resource_meta["tag_hash"],
                "config_hash": previous_hashes.get(arn, {}).get("config_hash"),
            }
            continue

        try:
            # IAM and other global resources may have region "" or "global"; use us-east-1 for session
            session_region = region if region and region != "global" else "us-east-1"
            regional_session = get_session(account_id, role_name, session_region)
            config = fetcher(regional_session, arn, region)
            stats["api_calls_made"] += 1

            drifted, new_config_hash = has_config_drifted(arn, config, previous_hashes)
            if drifted:
                stats["config_drifted"] += 1
                try:
                    write_resource_to_neo4j(
                        neo4j_driver,
                        account_id,
                        {
                            "arn": arn,
                                    "type": effective_resource_type,
                            "region": region,
                            "config": config,
                            "tags": resource_meta["tags"],
                        },
                    )
                except Exception as neo4j_err:
                    logger.warning(
                        "Neo4j write skipped for %s (e.g. Neo4j not running): %s",
                        arn[:80],
                        neo4j_err,
                    )

            new_hashes[arn] = {
                "tag_hash": resource_meta["tag_hash"],
                "config_hash": new_config_hash,
            }
            # Save raw config for rule engine
            ResourceConfig.objects.update_or_create(
                account_id=account_id,
                arn=arn,
                defaults={
                    "resource_type": effective_resource_type,
                    "region": region,
                    "config": config,
                    "tags": resource_meta.get("tags", {}),
                },
            )

            # Evaluate Rego rules for this resource and persist findings.
            # Never fail the inventory run if rule evaluation fails.
            try:
                from tasks.jobs.rule_engine.evaluator import evaluate_resource

                new_findings = evaluate_resource(
                    resource_type=effective_resource_type,
                    arn=arn,
                    account_id=account_id,
                    region=region,
                    config=config,
                    tags=resource_meta.get("tags", {}) or {},
                    inventory_run=run,
                    tenant_id=tenant.id,
                    provider_id=provider.id,
                )
                stats["new_findings"] = stats.get("new_findings", 0) + new_findings
            except Exception as e:
                logger.error("Rule engine failed for %s: %s", arn, e)

            stats["successfully_fetched"] += 1

        except Exception as e:
            logger.error("Failed %s: %s", arn, e)
            stats["fetch_failed"] += 1
            new_hashes[arn] = {
                "tag_hash": resource_meta["tag_hash"],
                "config_hash": previous_hashes.get(arn, {}).get("config_hash"),
            }
            continue

    for arn in delta["deleted"]:
        try:
            tombstone_resource(neo4j_driver, arn)
        except Exception as neo4j_err:
            logger.warning("Neo4j tombstone skipped for %s: %s", arn[:80], neo4j_err)
        ResourceConfig.objects.filter(account_id=account_id, arn=arn).update(
            config={"_deleted": True, "_deleted_at": str(timezone.now())}
        )
        new_hashes.pop(arn, None)

    save_hashes(account_id, new_hashes)

    # ----- Re-evaluate resources that have stored configs but zero findings -----
    # This catches the case where a previous scan stored configs but OPA was down
    # or resource types didn't match PACKAGE_MAP, so findings were never created.
    from api.models import Finding
    stored_configs = ResourceConfig.objects.filter(account_id=account_id).exclude(
        config__has_key="_deleted"
    )
    re_eval_count = 0
    for rc in stored_configs:
        if rc.arn in delta_arns:
            continue  # already evaluated above in this run
        has_findings = Finding.objects.filter(arn=rc.arn, tenant=tenant).exists()
        if has_findings:
            continue  # already has findings from a previous run
        try:
            from tasks.jobs.rule_engine.evaluator import evaluate_resource

            new_findings = evaluate_resource(
                resource_type=rc.resource_type,
                arn=rc.arn,
                account_id=rc.account_id,
                region=rc.region,
                config=rc.config,
                tags=rc.tags or {},
                inventory_run=run,
                tenant_id=tenant.id,
                provider_id=provider.id,
            )
            stats["new_findings"] = stats.get("new_findings", 0) + new_findings
            re_eval_count += 1
        except Exception as e:
            logger.error("Re-eval rule engine failed for %s: %s", rc.arn[:80], e)

    if re_eval_count:
        logger.info("Re-evaluated %s stored resources with missing findings", re_eval_count)


