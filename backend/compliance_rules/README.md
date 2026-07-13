# CloudSecure Compliance & Rule Engine

This folder holds **Prowler-to-Rego mapping** and rule-engine design docs. No code yet—tables only.

## Table 1 (per service)

For each Prowler check: **CheckID | Severity | FAIL condition (plain English) | Remediation CLI**.

## Table 2 (per service)

For each check: **Our Rego rule (replacement) | What we add that Prowler does not have** (India mapping, contextual severity, better remediation, compound checks, etc.).

## Files

| File | Service | Prowler path |
|------|---------|--------------|
| PROWLER_TO_REGO_S3.md | S3 | providers/aws/services/s3/ |
| PROWLER_TO_REGO_IAM.md | IAM | providers/aws/services/iam/ |
| PROWLER_TO_REGO_EC2.md | EC2 | providers/aws/services/ec2/ |
| PROWLER_TO_REGO_RDS.md | RDS | providers/aws/services/rds/ |
| PROWLER_TO_REGO_KMS.md | KMS | providers/aws/services/kms/ |
| PROWLER_TO_REGO_CLOUDTRAIL.md | CloudTrail | providers/aws/services/cloudtrail/ |

Reference: Prowler under `Cloud-Secure/prowler/` (same repo).

After all seven services: **Should I continue to writing Rego files?**
