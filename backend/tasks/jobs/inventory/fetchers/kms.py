import json

from ..throttle import with_backoff


@with_backoff()
def fetch_kms_config(session, arn: str, region: str) -> dict:
    kms = session.client("kms", region_name=region)
    key_id = arn.split("/")[-1]

    desc = kms.describe_key(KeyId=key_id)["KeyMetadata"]

    try:
        policy_str = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
        policy = json.loads(policy_str)
    except Exception:
        policy = None

    try:
        rotation = kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"]
    except Exception:
        rotation = None

    return {
        "key_id": key_id,
        "key_state": desc.get("KeyState"),
        "key_usage": desc.get("KeyUsage"),
        "key_manager": desc.get("KeyManager"),
        "rotation_enabled": rotation,
        "policy": policy,
        "deletion_date": str(desc.get("DeletionDate", "")),
    }
