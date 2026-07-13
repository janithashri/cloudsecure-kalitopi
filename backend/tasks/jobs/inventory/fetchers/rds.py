from ..throttle import with_backoff


@with_backoff()
def fetch_rds_config(session, arn: str, region: str) -> dict:
    rds = session.client("rds", region_name=region)
    db_id = arn.split(":")[-1] if ":" in arn else arn.split("/")[-1]
    r = rds.describe_db_instances(
        Filters=[{"Name": "db-instance-id", "Values": [db_id]}]
    )
    if not r["DBInstances"]:
        return {"arn": arn, "status": "not_found"}

    db = r["DBInstances"][0]
    return {
        "db_identifier": db.get("DBInstanceIdentifier"),
        "engine": db.get("Engine"),
        "engine_version": db.get("EngineVersion"),
        "publicly_accessible": db.get("PubliclyAccessible"),
        "storage_encrypted": db.get("StorageEncrypted"),
        "multi_az": db.get("MultiAZ"),
        "deletion_protection": db.get("DeletionProtection"),
        "backup_retention": db.get("BackupRetentionPeriod"),
        "ca_cert": db.get("CACertificateIdentifier"),
        "vpc_security_groups": [
            sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])
        ],
        "auto_minor_upgrade": db.get("AutoMinorVersionUpgrade"),
    }
