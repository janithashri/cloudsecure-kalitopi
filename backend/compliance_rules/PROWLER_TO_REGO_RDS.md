# RDS — Prowler checks and Rego mapping

## Service: `providers/aws/services/rds/`

---

## Table 1 — Every Prowler check: CheckID | Severity | FAIL condition (plain English) | Remediation CLI

| CheckID | Severity | FAIL Condition (plain English) | Remediation CLI |
|---------|----------|--------------------------------|-----------------|
| rds_instance_no_public_access | critical | RDS instance is publicly accessible (publicly_accessible = true). | aws rds modify-db-instance --db-instance-identifier &lt;id&gt; --no-publicly-accessible --apply-immediately |
| rds_instance_storage_encrypted | high | RDS instance storage is not encrypted. | (Cannot enable on existing; create new encrypted instance and migrate) |
| rds_instance_inside_vpc | high | RDS instance is not in a VPC (EC2-Classic or no db_subnet_group). | aws rds modify-db-instance ... --db-subnet-group-name &lt;name&gt; --apply-immediately |
| rds_instance_transport_encrypted | high | RDS instance does not enforce SSL/TLS for connections (rds.force_ssl not 1). | aws rds modify-db-parameter-group ... --parameters ParameterName='rds.force_ssl',ParameterValue='1',ApplyMethod='pending-reboot' |
| rds_instance_backup_enabled | medium | RDS instance has backup retention period 0 (backups disabled). | aws rds modify-db-instance --db-instance-identifier &lt;id&gt; --backup-retention-period 1 --apply-immediately |
| rds_instance_deletion_protection | medium | RDS instance does not have deletion protection enabled. | aws rds modify-db-instance ... --deletion-protection --apply-immediately |
| rds_instance_multi_az | medium | RDS instance is not Multi-AZ. | aws rds modify-db-instance ... --multi-az --apply-immediately |
| rds_instance_minor_version_upgrade_enabled | medium | RDS instance has auto minor version upgrade disabled. | aws rds modify-db-instance ... --auto-minor-version-upgrade --apply-immediately |
| rds_instance_iam_authentication_enabled | medium | RDS instance does not have IAM database authentication enabled. | aws rds modify-db-instance ... --enable-iam-database-authentication --apply-immediately |
| rds_instance_integration_cloudwatch_logs | medium | RDS instance does not export logs to CloudWatch. | aws rds modify-db-instance ... --cloudwatch-logs-export-configuration '{"EnableLogTypes":["..."]}' |
| rds_instance_certificate_expiration | high | RDS instance uses a deprecated or soon-expiring CA certificate. | aws rds modify-db-instance ... --ca-certificate-identifier rds-ca-rsa2048-g1 --apply-immediately |
| rds_instance_deprecated_engine_version | high | RDS instance runs a deprecated engine version. | aws rds modify-db-instance ... --engine-version &lt;supported&gt; --allow-major-version-upgrade --apply-immediately |
| rds_instance_protected_by_backup_plan | high | RDS instance is not included in an AWS Backup plan. | aws backup create-backup-selection ... |
| rds_instance_default_admin | medium | RDS instance uses default master username (e.g. admin, postgres). | (Change master user; no single CLI) |
| rds_instance_critical_event_subscription | medium | No RDS event subscription for critical events (failure, maintenance, config change). | aws rds create-event-subscription ... |
| rds_instance_copy_tags_to_snapshots | low | RDS instance does not copy tags to snapshots. | aws rds modify-db-instance ... --copy-tags-to-snapshot --apply-immediately |
| rds_instance_enhanced_monitoring_enabled | low | RDS instance does not have Enhanced Monitoring enabled. | aws rds modify-db-instance ... --monitoring-interval 60 --monitoring-role-arn &lt;arn&gt; |
| rds_instance_non_default_port | low | RDS instance uses default port (3306, 5432, etc.); recommend non-default. | aws rds modify-db-instance ... --db-port &lt;port&gt; |
| rds_instance_event_subscription_* | low/medium | Event subscriptions for parameter groups, security groups, etc. | aws rds create-event-subscription ... |
| rds_snapshots_public_access | critical | RDS snapshot is shared publicly (restore attribute includes all). | aws rds modify-db-snapshot-attribute ... --attribute-name restore --values-to-remove all |
| rds_snapshots_encrypted | high | RDS snapshot is not encrypted. | aws rds copy-db-snapshot ... --kms-key-id &lt;key&gt; (target encrypted) |
| rds_cluster_storage_encrypted | high | RDS cluster storage is not encrypted. | (Encrypt at creation) |
| rds_cluster_* (multi_az, backup, deletion_protection, cloudwatch_logs, iam_auth, etc.) | various | Same as instance-level but for cluster resource. | Same pattern: aws rds modify-db-cluster ... or create-event-subscription |

---

## Table 2 — Rego rule per check + what we add over Prowler

| Prowler CheckID | Our Rego rule (replacement) | What we add that Prowler does not have |
|-----------------|----------------------------|----------------------------------------|
| rds_instance_no_public_access | cis_aws_rds + india_aws_rds: deny when publicly_accessible true | CIS + DPDP/CERT-In/RBI; contextual severity (production); exact modify-db-instance CLI. |
| rds_instance_storage_encrypted | cis_aws_rds + india_aws_rds: deny when storage_encrypted false | CIS + DPDP/RBI; rationale; remediation “create encrypted replica”. |
| rds_instance_inside_vpc | cis_aws_rds + india_aws_rds: deny when not in VPC | CIS + India; modify-db-instance CLI. |
| rds_instance_transport_encrypted | cis_aws_rds + india_aws_rds: deny when force_ssl not enforced | CIS + CERT-In; modify-db-parameter-group CLI. |
| rds_instance_backup_enabled | cis_aws_rds: deny when backup_retention_period 0 | CIS; backup-retention-period CLI. |
| rds_instance_deletion_protection | cis_aws_rds + india_aws_rds: deny when deletion_protection false | CIS + India; deletion-protection CLI. |
| rds_instance_multi_az | cis_aws_rds: deny when multi_az false | CIS; multi-az CLI. |
| rds_instance_minor_version_upgrade_enabled | cis_aws_rds: deny when auto_minor_version_upgrade false | CIS; auto-minor-version-upgrade CLI. |
| rds_instance_iam_authentication_enabled | india_aws_rds + cis_aws_rds: deny when iam_authentication false | CERT-In + CIS; enable-iam-database-authentication CLI. |
| rds_instance_integration_cloudwatch_logs | cis_aws_rds: deny when no CloudWatch log export | CIS; cloudwatch-logs-export-configuration CLI. |
| rds_instance_certificate_expiration | india_aws_rds: deny when certificate deprecated/expiring | CERT-In; ca-certificate-identifier CLI. |
| rds_instance_deprecated_engine_version | india_aws_rds: deny when engine version deprecated | CERT-In; engine-version upgrade CLI. |
| rds_instance_protected_by_backup_plan | india_aws_rds: deny when not in backup plan | RBI/DPDP; create-backup-selection CLI. |
| rds_instance_default_admin | india_aws_rds: deny when default admin username | CERT-In; remediation steps. |
| rds_snapshots_public_access | cis_aws_rds + india_aws_rds: deny when snapshot publicly restorable | CIS + India; modify-db-snapshot-attribute CLI. |
| rds_snapshots_encrypted | cis_aws_rds: deny when snapshot not encrypted | copy-db-snapshot with KMS. |
| rds_cluster_* | Same pattern as instance in cis_aws_rds / india_aws_rds for cluster asset type | modify-db-cluster CLI; India mapping. |

---

*Next: KMS, CloudTrail.*
