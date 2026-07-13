#!/usr/bin/env python3
"""Re-fetch S3 configs and run consolidated rule + validation for all S3 buckets."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sqlalchemy import select

from app.core.database import SessionLocal
from app.db import repositories as repo
from app.models.orm import InventoryRun, Provider, ResourceConfig
from worker.jobs.inventory.aws import _get_fetcher
from worker.jobs.inventory.config import get_session
from worker.jobs.rule_engine.active_validator import reset_probe_state
from worker.jobs.rule_engine.evaluator import evaluate_resource


def main(provider_id: int = 1) -> None:
    reset_probe_state()
    with SessionLocal() as db:
        provider = db.get(Provider, provider_id)
        if not provider:
            print(f"Provider {provider_id} not found")
            sys.exit(1)
        run = repo.get_latest_inventory_run(db, provider_id)
        if not run:
            print("No inventory run found — run a scan first")
            sys.exit(1)
        configs = list(
            db.scalars(
                select(ResourceConfig).where(
                    ResourceConfig.account_id == provider.aws_account_id,
                    ResourceConfig.arn.like("arn:aws:s3:::%"),
                )
            ).all()
        )

    for rc in configs:
        fetcher, effective_type = _get_fetcher(rc.resource_type, rc.arn)
        if not fetcher:
            print(f"SKIP {rc.arn}: no fetcher")
            continue
        region = rc.region if rc.region and rc.region != "global" else "us-east-1"
        session = get_session(provider.aws_account_id, provider.inventory_role_name, region)
        config = fetcher(session, rc.arn, rc.region)
        merged_tags = {**(rc.tags or {}), **(config.get("tags") or {})}
        with SessionLocal() as db:
            repo.upsert_resource_config(
                db,
                account_id=rc.account_id,
                arn=rc.arn,
                resource_type=effective_type or rc.resource_type,
                region=rc.region,
                config=config,
                tags=merged_tags,
            )
            n = evaluate_resource(
                resource_type=effective_type or rc.resource_type,
                arn=rc.arn,
                account_id=rc.account_id,
                region=rc.region,
                config=config,
                tags=merged_tags,
                inventory_run_id=run.id,
                tenant_id=provider.tenant_id,
                provider_id=provider.id,
            )
        print(f"OK {config.get('bucket_name')}: tags={merged_tags} new_findings={n}")


if __name__ == "__main__":
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    main(pid)
