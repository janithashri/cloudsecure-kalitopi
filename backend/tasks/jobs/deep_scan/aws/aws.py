import os
import signal
from typing import Any

import aioboto3
import boto3
import neo4j
from cartography.config import Config as IngestionConfig
from cartography.intel import aws as cartography_aws

from providers.models import Provider as ProviderModel
from tasks.jobs.deep_scan import db_utils
from tasks.jobs.deep_scan.utils import stringify_exception

PER_SERVICE_TIMEOUT = int(os.environ.get("DEEP_SCAN_PER_SERVICE_TIMEOUT", "60"))


class _ServiceSyncTimeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise _ServiceSyncTimeout("Service sync timed out")


def start_aws_ingestion(
    neo4j_session: neo4j.Session,
    ingestion_config: IngestionConfig,
    api_provider: ProviderModel,
    cloud_provider,
    deep_scan,
) -> dict[str, dict[str, str]]:
    common_job_parameters = {
        "UPDATE_TAG": ingestion_config.update_tag,
        "permission_relationships_file": ingestion_config.permission_relationships_file,
        "aws_guardduty_severity_threshold": ingestion_config.aws_guardduty_severity_threshold,
        "aws_cloudtrail_management_events_lookback_hours": ingestion_config.aws_cloudtrail_management_events_lookback_hours,
        "experimental_aws_inspector_batch": ingestion_config.experimental_aws_inspector_batch,
    }
    boto3_session = _get_boto3_session(api_provider, cloud_provider)
    regions: list[str] = list(cloud_provider._enabled_regions)
    requested_syncs = list(cartography_aws.RESOURCE_FUNCTIONS.keys())
    sync_args = cartography_aws._build_aws_sync_kwargs(
        neo4j_session,
        boto3_session,
        regions,
        api_provider.aws_account_id,
        ingestion_config.update_tag,
        common_job_parameters,
    )
    cartography_aws.organizations.sync(
        neo4j_session,
        {api_provider.name: api_provider.aws_account_id},
        ingestion_config.update_tag,
        common_job_parameters,
    )
    db_utils.update_scan_progress(deep_scan, 3)
    common_job_parameters["AWS_ID"] = api_provider.aws_account_id
    cartography_aws._autodiscover_accounts(
        neo4j_session,
        boto3_session,
        api_provider.aws_account_id,
        ingestion_config.update_tag,
        common_job_parameters,
    )
    db_utils.update_scan_progress(deep_scan, 4)
    failed_syncs = _sync_all_services(api_provider, requested_syncs, sync_args, deep_scan)
    if "permission_relationships" in requested_syncs:
        cartography_aws.RESOURCE_FUNCTIONS["permission_relationships"](**sync_args)
    db_utils.update_scan_progress(deep_scan, 88)
    if "resourcegroupstaggingapi" in requested_syncs:
        cartography_aws.RESOURCE_FUNCTIONS["resourcegroupstaggingapi"](**sync_args)
    db_utils.update_scan_progress(deep_scan, 89)
    cartography_aws.run_scoped_analysis_job(
        "aws_ec2_iaminstanceprofile.json", neo4j_session, common_job_parameters
    )
    db_utils.update_scan_progress(deep_scan, 90)
    cartography_aws.run_analysis_job("aws_lambda_ecr.json", neo4j_session, common_job_parameters)
    db_utils.update_scan_progress(deep_scan, 91)
    cartography_aws.merge_module_sync_metadata(
        neo4j_session,
        group_type="AWSAccount",
        group_id=api_provider.aws_account_id,
        synced_type="AWSAccount",
        update_tag=ingestion_config.update_tag,
        stat_handler=cartography_aws.stat_handler,
    )
    db_utils.update_scan_progress(deep_scan, 92)
    del common_job_parameters["AWS_ID"]
    cartography_aws.run_cleanup_job(
        "aws_post_ingestion_principals_cleanup.json", neo4j_session, common_job_parameters
    )
    db_utils.update_scan_progress(deep_scan, 93)
    cartography_aws._perform_aws_analysis(requested_syncs, neo4j_session, common_job_parameters)
    db_utils.update_scan_progress(deep_scan, 94)
    return failed_syncs


def _get_boto3_session(api_provider: ProviderModel, cloud_provider) -> boto3.Session:
    boto3_session = cloud_provider.session.current_session
    aws_accounts = cartography_aws.organizations.get_aws_account_default(boto3_session)
    if not aws_accounts:
        raise Exception("No valid AWS credentials found.")
    authenticated_account_id = list(aws_accounts.values())[0]
    if api_provider.aws_account_id != authenticated_account_id:
        raise Exception("Credential mismatch for provider account.")
    if boto3_session.region_name is None:
        boto3_session._session.set_config_variable("region", cloud_provider.get_global_region())
    return boto3_session


def _get_aioboto3_session(boto3_session: boto3.Session) -> aioboto3.Session:
    return aioboto3.Session(botocore_session=boto3_session._session)


def _run_single_service(func_name: str, sync_args: dict[str, Any]) -> None:
    if func_name == "ecr:image_layers":
        cartography_aws.RESOURCE_FUNCTIONS[func_name](
            neo4j_session=sync_args.get("neo4j_session"),
            aioboto3_session=_get_aioboto3_session(sync_args.get("boto3_session")),
            regions=sync_args.get("regions"),
            current_aws_account_id=sync_args.get("current_aws_account_id"),
            update_tag=sync_args.get("update_tag"),
            common_job_parameters=sync_args.get("common_job_parameters"),
        )
    else:
        cartography_aws.RESOURCE_FUNCTIONS[func_name](**sync_args)


def _sync_all_services(api_provider: ProviderModel, requested_syncs: list[str], sync_args: dict[str, Any], deep_scan) -> dict[str, str]:
    current_progress = 4
    max_progress = 87
    n_steps = len(requested_syncs) - 2
    progress_step = (max_progress - current_progress) / max(n_steps, 1)
    failed_syncs: dict[str, str] = {}
    prev_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    try:
        for func_name in requested_syncs:
            if func_name in ("permission_relationships", "resourcegroupstaggingapi"):
                current_progress += progress_step
                db_utils.update_scan_progress(deep_scan, int(current_progress))
                continue
            current_progress += progress_step
            db_utils.update_scan_progress(deep_scan, int(current_progress))
            signal.alarm(PER_SERVICE_TIMEOUT)
            try:
                _run_single_service(func_name, sync_args)
            except _ServiceSyncTimeout:
                failed_syncs[func_name] = f"Timed out after {PER_SERVICE_TIMEOUT}s"
            except Exception as exc:
                failed_syncs[func_name] = stringify_exception(exc, context=f"Service sync failed: {func_name}")
            finally:
                signal.alarm(0)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, prev_handler)
    return failed_syncs
