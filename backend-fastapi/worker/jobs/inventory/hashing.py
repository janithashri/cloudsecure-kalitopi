import hashlib
import json


def compute_tag_hash(arn: str, resource_type: str, region: str, tags: dict) -> str:
    payload = {
        "arn": arn,
        "type": resource_type,
        "region": region,
        "tags": dict(sorted((tags or {}).items())),
    }
    return _sha256(payload)


def compute_config_hash(arn: str, config: dict) -> str:
    payload = {
        "arn": arn,
        "config": _normalise(config),
    }
    return _sha256(payload)


def _sha256(obj: dict) -> str:
    serialised = json.dumps(obj, sort_keys=True, default=str)
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


def _normalise(config):
    if isinstance(config, dict):
        return {k: _normalise(v) for k, v in sorted(config.items())}
    if isinstance(config, list):
        return sorted(
            [_normalise(i) for i in config],
            key=lambda x: json.dumps(x, default=str),
        )
    return config

