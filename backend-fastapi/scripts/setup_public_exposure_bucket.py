#!/usr/bin/env python3
"""
Create a deliberately public S3 bucket for live probe true-positive demos.

WARNING: This bucket allows anonymous ListBucket/GetObject. Use only in a
sandbox account and delete when the demo is done.

Usage:
  docker compose exec celery python scripts/setup_public_exposure_bucket.py
  docker compose exec celery python scripts/setup_public_exposure_bucket.py --register 1
  docker compose exec celery python scripts/setup_public_exposure_bucket.py --destroy
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.rule_engine.active_validator import reset_probe_state, validate_s3_exposure
from worker.jobs.rule_engine.input_builder import build_opa_input
from worker.jobs.rule_engine.opa_client import evaluate, load_all_rules

BUCKET = "cloudsecure-test-public-exposure-demo"
REGION = "us-east-1"
ACCOUNT = os.environ.get("AWS_ACCOUNT_ID", "123456789012")
DEMO_OBJECT_KEY = "cloudsecure-demo-public-read.txt"
DEMO_OBJECT_BODY = b"CloudSecure public exposure demo object - safe to delete.\n"

PUBLIC_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CloudSecurePublicExposureDemo",
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["s3:ListBucket", "s3:GetObject"],
            "Resource": [
                f"arn:aws:s3:::{BUCKET}",
                f"arn:aws:s3:::{BUCKET}/*",
            ],
        }
    ],
}


def fetch_s3_config(session, arn: str, region: str) -> dict:
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
    s3.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps(PUBLIC_POLICY))
    s3.put_bucket_tagging(
        Bucket=BUCKET,
        Tagging={"TagSet": [{"Key": "CloudSecureDemo", "Value": "public-exposure-true-positive"}]},
    )
    s3.put_object(Bucket=BUCKET, Key=DEMO_OBJECT_KEY, Body=DEMO_OBJECT_BODY, ContentType="text/plain")
    print("Applied anonymous ListBucket/GetObject policy, BPA disabled, demo object uploaded")


def destroy_bucket(session) -> None:
    s3 = session.client("s3", region_name=REGION)
    try:
        s3.head_bucket(Bucket=BUCKET)
    except ClientError:
        print(f"Bucket {BUCKET} not found — nothing to delete")
        return

    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=BUCKET):
        to_delete = []
        for version in page.get("Versions", []) + page.get("DeleteMarkers", []):
            to_delete.append({"Key": version["Key"], "VersionId": version["VersionId"]})
        if to_delete:
            s3.delete_objects(Bucket=BUCKET, Delete={"Objects": to_delete})

    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET):
        keys = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=BUCKET, Delete={"Objects": keys})

    try:
        s3.delete_bucket_policy(Bucket=BUCKET)
    except ClientError:
        pass
    try:
        s3.delete_public_access_block(Bucket=BUCKET)
    except ClientError:
        pass
    s3.delete_bucket(Bucket=BUCKET)
    print(f"Deleted bucket {BUCKET}")


def analyze(session, *, skip_probe: bool = False) -> dict:
    arn = f"arn:aws:s3:::{BUCKET}"
    config = fetch_s3_config(session, arn, REGION)
    config["tags"] = {"CloudSecureDemo": "public-exposure-true-positive"}

    opa_input = build_opa_input("s3:bucket", arn, REGION, ACCOUNT, config)
    load_all_rules()
    consolidated = evaluate("cloudsecure/rules/consolidated_s3", opa_input)

    if skip_probe:
        probe = {"probe_type": "s3_unauth_head_get", "classification": "skipped_for_register"}
    else:
        reset_probe_state()
        probe = validate_s3_exposure(BUCKET, REGION)

    return {
        "bucket": BUCKET,
        "policy_status_public_aws": config.get("policy_status_public"),
        "exposure": opa_input["input"]["asset"].get("exposure"),
        "consolidated_rule_hits": len(consolidated),
        "consolidated_matched_conditions": [m.get("matched_condition") for m in consolidated],
        "live_probe": probe,
        "expected_story": {
            "static_rule_fires": len(consolidated) > 0,
            "live_probe_true_positive": probe.get("classification") == "true_positive",
            "http_status": probe.get("http_status"),
        },
    }


def register_in_cloudsecure(provider_id: int, session) -> None:
    from sqlalchemy import select

    from app.core.database import SessionLocal
    from app.db import repositories as repo
    from app.models.orm import Provider, ResourceConfig
    from worker.jobs.rule_engine.evaluator import evaluate_resource

    arn = f"arn:aws:s3:::{BUCKET}"
    config = fetch_s3_config(session, arn, REGION)
    tags = {"CloudSecureDemo": "public-exposure-true-positive"}

    with SessionLocal() as db:
        provider = db.get(Provider, provider_id)
        if not provider:
            raise RuntimeError(f"Provider {provider_id} not found")
        run = repo.get_latest_inventory_run(db, provider_id)
        if not run:
            raise RuntimeError("No inventory run found — run a scan first")

        repo.upsert_resource_config(
            db,
            account_id=provider.aws_account_id,
            arn=arn,
            resource_type="AWS::S3::Bucket",
            region=REGION,
            config=config,
            tags=tags,
        )
        db.commit()

        n = evaluate_resource(
            resource_type="AWS::S3::Bucket",
            arn=arn,
            account_id=provider.aws_account_id,
            region=REGION,
            config=config,
            tags=tags,
            inventory_run_id=run.id,
            tenant_id=provider.tenant_id,
            provider_id=provider.id,
        )

        finding = db.scalars(
            select(ResourceConfig).where(ResourceConfig.arn == arn)
        ).first()
        print(f"Registered {arn} in CloudSecure; new_findings={n}")

        from app.models.orm import Finding

        consolidated = db.scalars(
            select(Finding).where(Finding.arn == arn, Finding.rule_id == "CONSOLIDATED-S3-001")
        ).first()
        if consolidated:
            print(
                f"Finding status={consolidated.status} "
                f"probe={((consolidated.raw_finding or {}).get('validation_probe') or {}).get('classification')}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Public S3 exposure demo bucket")
    parser.add_argument("--register", type=int, metavar="PROVIDER_ID", help="Upsert bucket + run rule engine")
    parser.add_argument("--destroy", action="store_true", help="Delete demo bucket and contents")
    args = parser.parse_args()

    session = boto3.Session(region_name=REGION)

    if args.destroy:
        destroy_bucket(session)
        return 0

    ensure_bucket(session)
    result = analyze(session, skip_probe=args.register is not None)
    print(json.dumps(result, indent=2, default=str))

    ok = result["expected_story"]["static_rule_fires"] and (
        result["expected_story"]["live_probe_true_positive"] or args.register is not None
    )
    if args.register is not None:
        reset_probe_state()
        register_in_cloudsecure(args.register, session)

    print()
    if ok:
        print("PASS: Public exposure demo bucket — static rule fires AND anonymous probe returns 200.")
    else:
        print("CHECK: Review results above — bucket may not be anonymously reachable yet.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
