"""
OPA client: load policies and evaluate input. On any OPA error: log warning, return empty list, never raise.
"""
import logging
import os
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


def _opa_base_url():
    from django.conf import settings
    return (getattr(settings, "OPA_URL", None) or os.environ.get("OPA_URL", "http://localhost:8181")).rstrip("/")


def load_policy(policy_id: str, rego_content: str) -> bool:
    """PUT /v1/policies/{policy_id}. Load a single Rego policy. Returns True on success."""
    base = _opa_base_url()
    url = f"{base}/v1/policies/{policy_id}"
    try:
        # OPA expects the Rego in the request body as raw text or form
        r = requests.put(url, data=rego_content.encode("utf-8"), headers={"Content-Type": "text/plain"}, timeout=10)
        if r.status_code != 200:
            logger.warning("OPA load_policy %s failed: %s %s", policy_id, r.status_code, r.text[:200])
            return False
        return True
    except Exception as e:
        logger.warning("OPA load_policy %s error: %s", policy_id, e)
        return False


def evaluate(package_path: str, input_data: dict) -> list:
    """
    POST /v1/data/{package_path}. Returns result.deny or [].
    package_path e.g. "cloudsecure/rules/cis_aws_s3" (slashes) -> OPA query data.cloudsecure.rules.cis_aws_s3.deny
    """
    base = _opa_base_url()
    # OPA data API: /v1/data/foo/bar/baz -> data.foo.bar.baz
    path = package_path.replace(".", "/")
    url = f"{base}/v1/data/{path}"
    try:
        r = requests.post(url, json=input_data, timeout=10)
        if r.status_code != 200:
            logger.warning("OPA evaluate %s failed: %s %s", package_path, r.status_code, r.text[:200])
            return []
        data = r.json()
        result = data.get("result")
        if result is None:
            return []
        deny = result.get("deny")
        if deny is None:
            return []
        return deny if isinstance(deny, list) else []
    except Exception as e:
        logger.warning("OPA evaluate %s error: %s", package_path, e)
        return []


def load_all_rules(rules_dir: str | None = None) -> None:
    """Walk rules_dir, load every .rego file into OPA. policy_id = file stem (e.g. cis_aws_s3)."""
    from django.conf import settings
    dir_path = rules_dir or getattr(settings, "RULES_DIR", None)
    if not dir_path or not os.path.isdir(dir_path):
        logger.warning("RULES_DIR not found or not a directory: %s", dir_path)
        return
    loaded = 0
    for path in Path(dir_path).rglob("*.rego"):
        if path.name.startswith("."):
            continue
        try:
            content = path.read_text(encoding="utf-8")
            policy_id = path.stem
            if load_policy(policy_id, content):
                loaded += 1
        except Exception as e:
            logger.warning("Failed to load rule file %s: %s", path, e)
    logger.info("OPA: loaded %s Rego policies from %s", loaded, dir_path)
