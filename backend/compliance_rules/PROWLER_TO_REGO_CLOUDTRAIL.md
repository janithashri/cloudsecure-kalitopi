# CloudTrail — Prowler checks and Rego mapping

## Service: `providers/aws/services/cloudtrail/`

---

## Table 1 — Every Prowler check: CheckID | Severity | FAIL condition (plain English) | Remediation CLI

| CheckID | Severity | FAIL Condition (plain English) | Remediation CLI |
|---------|----------|--------------------------------|-----------------|
| cloudtrail_multi_region_enabled | high | No CloudTrail trail is multi-region and logging (at least one trail must be multi-region and enabled). | (Create/update trail: enable multi-region and logging via console or CLI) |
| cloudtrail_multi_region_enabled_logging_management_events | low | Multi-region trail does not log management events (Read/Write). | (Configure event selectors) |
| cloudtrail_logs_s3_bucket_is_not_publicly_accessible | critical | The S3 bucket used for CloudTrail logs is publicly accessible (ACL or policy). | aws s3api put-bucket-acl --bucket &lt;bucket&gt; --acl private |
| cloudtrail_logs_s3_bucket_access_logging_enabled | medium | The S3 bucket used for CloudTrail logs does not have server access logging enabled. | aws s3api put-bucket-logging --bucket &lt;bucket&gt; --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"&lt;TARGET&gt;"}}' |
| cloudtrail_log_file_validation_enabled | medium | CloudTrail trail does not have log file validation enabled. | aws cloudtrail update-trail --name &lt;trail_name&gt; --enable-log-file-validation |
| cloudtrail_kms_encryption_enabled | medium | CloudTrail trail does not use KMS encryption for log files. | aws cloudtrail update-trail --name &lt;trail_name&gt; --kms-key-id &lt;kms_key_arn&gt; |
| cloudtrail_cloudwatch_logging_enabled | low | CloudTrail trail is not integrated with CloudWatch Logs. | aws cloudtrail update-trail --name &lt;trail_name&gt; --cloud-watch-logs-log-group-arn &lt;arn&gt; --cloud-watch-logs-role-arn &lt;role_arn&gt; |
| cloudtrail_insights_exist | low | CloudTrail trail does not have Insights events enabled. | aws cloudtrail put-insight-selectors --trail-name &lt;TRAIL_NAME&gt; --insight-selectors '[{"InsightType":"ApiCallRateInsight"}]' |
| cloudtrail_bucket_requires_mfa_delete | medium | The S3 bucket used for CloudTrail logs does not have MFA Delete enabled on versioning. | aws s3api put-bucket-versioning --bucket &lt;bucket&gt; --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa "&lt;MFA&gt;" |
| cloudtrail_s3_dataevents_read_enabled | low | Trail does not log S3 data events (Read). | aws cloudtrail put-event-selectors ... ReadOnly, DataResources S3 |
| cloudtrail_s3_dataevents_write_enabled | low | Trail does not log S3 data events (Write). | aws cloudtrail put-event-selectors ... WriteOnly, DataResources S3 |
| cloudtrail_threat_detection_privilege_escalation | critical | (Threat detection) Privilege escalation pattern detected in CloudTrail. | (Operational: revoke keys, investigate) |
| cloudtrail_threat_detection_llm_jacking | critical | (Threat detection) LLM jacking pattern detected. | (Operational) |
| cloudtrail_threat_detection_enumeration | critical | (Threat detection) Enumeration pattern detected (e.g. excessive List* calls). | aws iam update-access-key ... --status Inactive (if key abused) |

---

## Table 2 — Rego rule per check + what we add over Prowler

| Prowler CheckID | Our Rego rule (replacement) | What we add that Prowler does not have |
|-----------------|----------------------------|----------------------------------------|
| cloudtrail_multi_region_enabled | cis_aws_cloudtrail + india_aws_cloudtrail: deny when no multi-region trail with logging enabled | CIS + CERT-In 2022; step-by-step remediation; exact create-trail/update-trail CLI. |
| cloudtrail_multi_region_enabled_logging_management_events | cis_aws_cloudtrail: deny when trail does not log management events (Read/Write) | CIS; put-event-selectors CLI. |
| cloudtrail_logs_s3_bucket_is_not_publicly_accessible | cis_aws_cloudtrail + india_aws_cloudtrail: deny when trail’s S3 bucket is public (from S3 asset or trail config) | CIS + CERT-In; put-bucket-acl / put-public-access-block CLI. |
| cloudtrail_logs_s3_bucket_access_logging_enabled | cis_aws_cloudtrail + india_aws_cloudtrail: deny when trail’s S3 bucket has no access logging | CIS + CERT-In; put-bucket-logging CLI. |
| cloudtrail_log_file_validation_enabled | cis_aws_cloudtrail + india_aws_cloudtrail: deny when log_file_validation_enabled false | CIS + CERT-In; update-trail --enable-log-file-validation CLI. |
| cloudtrail_kms_encryption_enabled | cis_aws_cloudtrail + india_aws_cloudtrail: deny when kms_key_id null/empty | CIS + CERT-In/RBI; update-trail --kms-key-id CLI. |
| cloudtrail_cloudwatch_logging_enabled | cis_aws_cloudtrail: deny when cloudwatch_logs_log_group_arn empty | CIS; update-trail CloudWatch CLI. |
| cloudtrail_insights_exist | india_aws_cloudtrail (optional): deny when no insight selectors | CERT-In; put-insight-selectors CLI. |
| cloudtrail_bucket_requires_mfa_delete | cis_aws_cloudtrail: deny when trail bucket versioning without MFA Delete | CIS 2.1.2; put-bucket-versioning MFA CLI. |
| cloudtrail_s3_dataevents_* | Optional (low): deny when no S3 data events for read/write | put-event-selectors CLI. |
| cloudtrail_threat_detection_* | Omit in v1 (behavioral detection; not config-only) | When added: CERT-In incident response mapping. |

---

## Summary

All seven services are covered:

- **S3** — PROWLER_TO_REGO_S3.md  
- **IAM** — PROWLER_TO_REGO_IAM.md  
- **EC2** — PROWLER_TO_REGO_EC2.md  
- **RDS** — PROWLER_TO_REGO_RDS.md  
- **KMS** — PROWLER_TO_REGO_KMS.md  
- **CloudTrail** — PROWLER_TO_REGO_CLOUDTRAIL.md  

**Should I continue to writing Rego files?**
