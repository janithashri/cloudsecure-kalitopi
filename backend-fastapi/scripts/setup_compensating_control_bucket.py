#!/usr/bin/env python3
"""
Create/update the compensating-control demo bucket and run consolidated rule + live probe.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

import importlib.util

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.rule_engine.active_validator import reset_probe_state, validate_s3_exposure
from worker.jobs.rule_engine.input_builder import build_opa_input
from worker.jobs.rule_engine.opa_client import evaluate, load_all_rules


def fetch_s3_config(session, arn: str, region: str) -> dict:
    """Minimal fetcher copy — avoids inventory package DB imports."""
    bucket_name = arn.split(":::")[-1]
    s3 = session.client("s3", region_name=region)
    config = {"bucket_name": bucket_name}

    try:
        r = s3.get_public_access_block(Bucket=bucket_name)
        config["public_access_block"] = r.get("PublicAccessBlockConfiguration", {})
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NoSuchPublicAccessBlockConfiguration":
            raise
        config["public_access_block"] = None

    try:
        r = s3.get_bucket_policy(Bucket=bucket_name)
        config["policy"] = json.loads(r["Policy"])
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NoSuchBucketPolicy":
            raise
        config["policy"] = None

    try:
        r = s3.get_bucket_policy_status(Bucket=bucket_name)
        config["policy_status_public"] = r.get("PolicyStatus", {}).get("IsPublic") is True
    except ClientError:
        config["policy_status_public"] = False

    try:
        r = s3.get_bucket_acl(Bucket=bucket_name)
        config["acl_grants"] = [
            {
                "grantee": g["Grantee"].get("URI", g["Grantee"].get("ID", "")),
                "permission": g["Permission"],
            }
            for g in r.get("Grants", [])
        ]
    except ClientError:
        config["acl_grants"] = []

    config.setdefault("encryption", None)
    config.setdefault("versioning", "Disabled")
    config.setdefault("logging_enabled", False)
    return config

BUCKET = "cloudsecure-test-compensating-control"
REGION = "us-east-1"
ACCOUNT = os.environ.get("AWS_ACCOUNT_ID", "123456789012")

POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET}/*",
            "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
        }
    ],
}


def ensure_bucket(session) -> None:
    s3 = session.client("s3", region_name=REGION)
    try:
        s3.head_bucket(Bucket=BUCKET)
        print(f"Bucket {BUCKET} already exists")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("404", "NoSuchBucket", "403"):
            s3.create_bucket(Bucket=BUCKET)
            print(f"Created bucket {BUCKET}")
        else:
            raise

    s3.put_public_access_block(
        Bucket=BUCKET,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    s3.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps(POLICY))
    s3.put_bucket_tagging(
        Bucket=BUCKET,
        Tagging={"TagSet": [{"Key": "DataClassification", "Value": "sensitive"}]},
    )
    print("Applied IP-restricted wildcard policy, BPA disabled, sensitive tag")


def analyze(session) -> dict:
    arn = f"arn:aws:s3:::{BUCKET}"
    config = fetch_s3_config(session, arn, REGION)
    config["tags"] = {"DataClassification": "sensitive"}
    opa_input = build_opa_input("s3:bucket", arn, REGION, ACCOUNT, config)
    asset = opa_input["input"]["asset"]

    load_all_rules()
    consolidated = evaluate("cloudsecure/rules/consolidated_s3", opa_input)
    old_public = []
    for pkg in ["cloudsecure/rules/cis_aws_s3", "cloudsecure/rules/india_aws_s3"]:
        for msg in evaluate(pkg, opa_input):
            rid = msg.get("rule_id", "")
            if rid in {
                "CIS-2.1.4",
                "CIS-2.1.4-PUBLIC",
                "CIS-2.1-CROSS-ACCOUNT",
                "DPDP-S3-PUBLIC",
                "DPDP-S3-IS-PUBLIC",
                "RBI-S3-CROSS-ACCOUNT",
            }:
                old_public.append(rid)

    reset_probe_state()
    probe = validate_s3_exposure(BUCKET, REGION)

    statements = asset.get("bucket_policy_statements", [])
    return {
        "bucket": BUCKET,
        "policy_status_public_aws": config.get("policy_status_public"),
        "exposure": asset.get("exposure"),
        "sensitive_data": asset.get("sensitive_data"),
        "bucket_policy_statements": statements,
        "condition_3_4_should_exclude_statement": all(
            s.get("restricted_access_condition") for s in statements if s.get("principal_aws") == "*"
        ),
        "consolidated_rule_hits": consolidated,
        "consolidated_matched_conditions": [m.get("matched_condition") for m in consolidated],
        "old_fragmented_public_rule_ids": old_public,
        "live_probe": probe,
        "expected_story": {
            "static_rule_fires": len(consolidated) > 0,
            "condition_4_fires": any(
                m.get("matched_condition") == "public_allow_policy_bpa_disabled" for m in consolidated
            ),
            "live_probe_false_positive": probe.get("classification") == "false_positive",
        },
    }


def main():
    session = boto3.Session(region_name=REGION)
    ensure_bucket(session)
    result = analyze(session)
    print(json.dumps(result, indent=2, default=str))

    ok = (
        result["condition_3_4_should_exclude_statement"]
        and not result["expected_story"]["condition_4_fires"]
        and result["expected_story"]["static_rule_fires"]
        and result["expected_story"]["live_probe_false_positive"]
    )
    print()
    if ok:
        print("PASS: Compensating-control demo validated with live AWS data.")
    else:
        print("CHECK: Review results above — one or more expectations not met.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
