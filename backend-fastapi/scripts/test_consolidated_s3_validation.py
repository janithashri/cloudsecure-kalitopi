#!/usr/bin/env python3
"""
Test consolidated S3 rule + active behavioral validation on 5 bucket scenarios.

Usage (from backend-fastapi with OPA running):
  set PYTHONPATH=.
  set OPA_URL=http://localhost:8181
  python scripts/test_consolidated_s3_validation.py

Optional live S3 probes (requires AWS creds + real bucket names):
  python scripts/test_consolidated_s3_validation.py --live bucket1 bucket2 ...
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from worker.jobs.rule_engine.active_validator import reset_probe_state, validate_s3_exposure
from worker.jobs.rule_engine.input_builder import build_opa_input
from worker.jobs.rule_engine.opa_client import evaluate, load_all_rules

SUPPRESSED_S3_PUBLIC_RULE_IDS = {
    "CIS-2.1.4",
    "CIS-2.1.4-PUBLIC",
    "CIS-2.1-CROSS-ACCOUNT",
    "DPDP-S3-PUBLIC",
    "DPDP-S3-IS-PUBLIC",
    "RBI-S3-CROSS-ACCOUNT",
}

ACCOUNT = "123456789012"
REGION = "us-east-1"

# Five representative test buckets mirroring Paper A/B evaluation scenarios
TEST_BUCKETS = [
    {
        "name": "bucket-1-secure-bpa-on",
        "description": "Fully locked down — should NOT fire consolidated rule",
        "expected_consolidated": False,
        "expected_old_public_rules": 0,
        "config": {
            "bucket_name": "bucket-1-secure-bpa-on",
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "policy": None,
            "policy_status_public": False,
            "acl_grants": [],
            "encryption": [{"SSEAlgorithm": "AES256"}],
            "versioning": "Enabled",
            "logging_enabled": True,
            "tags": {"environment": "production"},
        },
    },
    {
        "name": "bucket-2-public-acl-read",
        "description": "Condition 1: AllUsers READ ACL grant",
        "expected_consolidated": True,
        "expected_condition": "public_acl_grants",
        "config": {
            "bucket_name": "bucket-2-public-acl-read",
            "public_access_block": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "policy": None,
            "policy_status_public": False,
            "acl_grants": [
                {
                    "grantee": "http://acs.amazonaws.com/groups/global/AllUsers",
                    "permission": "READ",
                }
            ],
            "encryption": None,
            "versioning": "Disabled",
            "logging_enabled": False,
        },
    },
    {
        "name": "bucket-3-policy-public-facing",
        "description": "Condition 2: policy_status_public + public_facing exposure",
        "expected_consolidated": True,
        "expected_condition": "public_policy_and_exposure_facing",
        "config": {
            "bucket_name": "bucket-3-policy-public-facing",
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
            "policy_status_public": True,
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::bucket-3-policy-public-facing/*",
                    }
                ],
            },
            "acl_grants": [],
            "encryption": None,
            "versioning": "Disabled",
            "logging_enabled": False,
        },
    },
    {
        "name": "bucket-4-bpa-off-wildcard-no-condition",
        "description": "Condition 4: wildcard Allow + RestrictPublicBuckets disabled",
        "expected_consolidated": True,
        "expected_condition": "public_allow_policy_bpa_disabled",
        "config": {
            "bucket_name": "bucket-4-bpa-off-wildcard-no-condition",
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
            "policy_status_public": True,
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::bucket-4-bpa-off-wildcard-no-condition/*",
                    }
                ],
            },
            "acl_grants": [],
            "encryption": None,
            "versioning": "Disabled",
            "logging_enabled": False,
        },
    },
    {
        "name": "bucket-5-sensitive-public-facing",
        "description": "Condition 5: public_facing + DataClassification=sensitive tag",
        "expected_consolidated": True,
        "expected_condition": "public_facing_sensitive_data",
        "config": {
            "bucket_name": "bucket-5-sensitive-public-facing",
            "public_access_block": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
            "policy": None,
            "policy_status_public": False,
            "acl_grants": [],
            "encryption": None,
            "versioning": "Disabled",
            "logging_enabled": False,
            "tags": {"DataClassification": "sensitive"},
        },
    },
]


def _count_old_public_hits(denials: list[dict]) -> tuple[int, list[str]]:
    hits = []
    for msg in denials:
        rule_id = msg.get("rule_id", "")
        if rule_id in SUPPRESSED_S3_PUBLIC_RULE_IDS:
            hits.append(rule_id)
    return len(hits), hits


def run_opa_tests() -> dict:
    load_all_rules()
    results = []
    total_old = 0
    total_consolidated = 0

    for bucket in TEST_BUCKETS:
        arn = f"arn:aws:s3:::{bucket['name']}"
        opa_input = build_opa_input("s3:bucket", arn, REGION, ACCOUNT, bucket["config"])

        old_denials = []
        for pkg in ["cloudsecure/rules/cis_aws_s3", "cloudsecure/rules/india_aws_s3"]:
            for msg in evaluate(pkg, opa_input):
                rule_id = msg.get("rule_id", "")
                if rule_id in SUPPRESSED_S3_PUBLIC_RULE_IDS:
                    old_denials.append(msg)

        consolidated = evaluate("cloudsecure/rules/consolidated_s3", opa_input)
        old_count, old_rules = _count_old_public_hits(old_denials)
        consolidated_count = len(consolidated)
        total_old += old_count
        total_consolidated += consolidated_count

        matched_conditions = [m.get("matched_condition") for m in consolidated if isinstance(m, dict)]
        pass_consolidated = bucket["expected_consolidated"] == (consolidated_count > 0)
        pass_condition = True
        if bucket.get("expected_condition"):
            pass_condition = bucket["expected_condition"] in matched_conditions

        results.append(
            {
                "bucket": bucket["name"],
                "description": bucket["description"],
                "old_fragmented_public_alerts": old_count,
                "old_rule_ids": old_rules,
                "consolidated_alerts": consolidated_count,
                "matched_conditions": matched_conditions,
                "expected_consolidated": bucket["expected_consolidated"],
                "pass_consolidated": pass_consolidated,
                "pass_condition": pass_condition,
                "exposure": opa_input["input"]["asset"].get("exposure"),
                "sensitive_data": opa_input["input"]["asset"].get("sensitive_data"),
            }
        )

    reduction_pct = round((1 - total_consolidated / total_old) * 100, 1) if total_old else 0.0
    return {
        "buckets_tested": len(results),
        "total_old_fragmented_public_alerts": total_old,
        "total_consolidated_alerts": total_consolidated,
        "alert_reduction_pct": reduction_pct,
        "all_pass": all(r["pass_consolidated"] and r["pass_condition"] for r in results),
        "results": results,
    }


def run_live_probes(bucket_names: list[str]) -> list[dict]:
    reset_probe_state()
    probes = []
    for name in bucket_names[:5]:
        probe = validate_s3_exposure(name, REGION)
        probes.append(probe)
    return probes


def main():
    parser = argparse.ArgumentParser(description="Test consolidated S3 rule + active validation")
    parser.add_argument("--live", nargs="*", help="Optional real bucket names for live S3 probes")
    args = parser.parse_args()

    print("=" * 70)
    print("STAGE 1: Consolidated S3 Rule (OPA evaluation on 5 test scenarios)")
    print("=" * 70)

    opa_results = run_opa_tests()
    print(json.dumps(opa_results, indent=2))

    print()
    print("Per-bucket summary:")
    for r in opa_results["results"]:
        status = "PASS" if r["pass_consolidated"] and r["pass_condition"] else "FAIL"
        print(
            f"  [{status}] {r['bucket']}: old={r['old_fragmented_public_alerts']} "
            f"-> consolidated={r['consolidated_alerts']} "
            f"conditions={r['matched_conditions'] or 'none'}"
        )

    print()
    print(
        f"Consolidation funnel: {opa_results['total_old_fragmented_public_alerts']} "
        f"-> {opa_results['total_consolidated_alerts']} "
        f"({opa_results['alert_reduction_pct']}% reduction)"
    )

    if args.live is not None:
        live_buckets = args.live if args.live else [b["name"] for b in TEST_BUCKETS]
        print()
        print("=" * 70)
        print("STAGE 2: Active Behavioral Validation (live S3 probes)")
        print("=" * 70)
        probes = run_live_probes(live_buckets)
        print(json.dumps(probes, indent=2))
        for p in probes:
            print(
                f"  {p['resource']}: {p['classification']} "
                f"({p.get('compensating_control') or 'exploitable'}) "
                f"{p.get('duration_ms')}ms"
            )

    sys.exit(0 if opa_results["all_pass"] else 1)


if __name__ == "__main__":
    main()
