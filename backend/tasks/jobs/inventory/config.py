from functools import lru_cache

import boto3
from botocore.config import Config

BOTO_CONFIG = Config(
    retries={
        "max_attempts": 8,
        "mode": "adaptive",
    },
    max_pool_connections=10,
)


@lru_cache(maxsize=256)
def get_session(account_id: str, role_name: str, region: str) -> boto3.Session:
    sts = boto3.client("sts", config=BOTO_CONFIG)
    assumed = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
        RoleSessionName="CloudSecureInventory",
        DurationSeconds=3600,
    )
    creds = assumed["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def get_client(account_id: str, role_name: str, service: str, region: str):
    session = get_session(account_id, role_name, region)
    return session.client(service, config=BOTO_CONFIG)

