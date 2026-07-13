import os
from dataclasses import dataclass
from typing import Callable

from worker.jobs.deep_scan.aws.aws import start_aws_ingestion

BATCH_SIZE = int(os.environ.get("CLOUDSECURE_DEEP_SCAN_BATCH_SIZE", "1000"))
CLOUDSECURE_FINDING_LABEL = "CloudSecureFinding"
PROVIDER_RESOURCE_LABEL = "ProviderResource"
INTERNET_NODE_LABEL = "Internet"


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    root_node_label: str
    uid_field: str
    resource_label: str
    ingestion_function: Callable


AWS_CONFIG = ProviderConfig(
    name="aws",
    root_node_label="AWSAccount",
    uid_field="arn",
    resource_label="AWSResource",
    ingestion_function=start_aws_ingestion,
)

PROVIDER_CONFIGS: dict[str, ProviderConfig] = {"aws": AWS_CONFIG}


def get_ingestion_function(provider_type: str) -> Callable | None:
    config = PROVIDER_CONFIGS.get(provider_type)
    return config.ingestion_function if config else None


def get_root_node_label(provider_type: str) -> str:
    config = PROVIDER_CONFIGS.get(provider_type)
    return config.root_node_label if config else "UnknownProviderAccount"


def get_uid_field(provider_type: str) -> str:
    config = PROVIDER_CONFIGS.get(provider_type)
    return config.uid_field if config else "id"


def get_resource_label(provider_type: str) -> str:
    config = PROVIDER_CONFIGS.get(provider_type)
    return config.resource_label if config else "UnknownProviderResource"
