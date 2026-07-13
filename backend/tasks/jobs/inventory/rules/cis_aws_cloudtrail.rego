# CloudSecure CIS AWS Foundations Benchmark — CloudTrail
# Prowler reference: providers/aws/services/cloudtrail/
# Input: input.asset (asset_type: "cloudtrail_trail")

package cloudsecure.rules.cis_aws_cloudtrail

import rego.v1

default allow := true

# ---------------------------------------------------------------------------
# Multi-region trail with logging enabled
# Real-world impact: Single-region trails miss events in other regions; critical for incident response.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	not input.asset.is_multi_region
	msg := {
		"rule_id": "CIS-3.1.1",
		"issue": sprintf("CloudTrail trail '%v' in region '%v' is not a multi-region trail", [input.asset.name, input.asset.region]),
		"severity": "HIGH",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "3 Logging",
		"status": "FAIL",
		"compliance": ["CIS 3.1", "CERT-In 2022"],
		"remediation": sprintf("Create or update trail to be multi-region: aws cloudtrail update-trail --name %v --is-multi-region-trail", [input.asset.name]),
	}
}

deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	not input.asset.is_logging
	msg := {
		"rule_id": "CIS-3.1.2",
		"issue": sprintf("CloudTrail trail '%v' is not logging", [input.asset.name]),
		"severity": "CRITICAL",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "3 Logging",
		"status": "FAIL",
		"compliance": ["CIS 3.1", "CERT-In 2022", "DPDP 2023"],
		"remediation": sprintf("aws cloudtrail start-logging --name %v", [input.asset.name]),
	}
}

# ---------------------------------------------------------------------------
# Log file validation
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	not input.asset.log_file_validation_enabled
	msg := {
		"rule_id": "CIS-3.2.1",
		"issue": sprintf("CloudTrail trail '%v' does not have log file validation enabled", [input.asset.name]),
		"severity": "MEDIUM",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "3 Logging",
		"status": "FAIL",
		"compliance": ["CIS 3.2", "CERT-In 2022"],
		"remediation": sprintf("aws cloudtrail update-trail --name %v --enable-log-file-validation", [input.asset.name]),
	}
}

# ---------------------------------------------------------------------------
# KMS encryption for logs
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	not input.asset.kms_encryption_enabled
	msg := {
		"rule_id": "CIS-3.3.1",
		"issue": sprintf("CloudTrail trail '%v' does not use KMS encryption for log files", [input.asset.name]),
		"severity": "MEDIUM",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "3 Logging",
		"status": "FAIL",
		"compliance": ["CIS 3.3", "CERT-In 2022", "RBI"],
		"remediation": sprintf("aws cloudtrail update-trail --name %v --kms-key-id <kms_key_arn_or_alias>", [input.asset.name]),
	}
}

# ---------------------------------------------------------------------------
# S3 bucket for CloudTrail logs must not be public (handled by S3 rules when bucket is in scope)
# Here we only flag if we have trail-level info about bucket public state.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	input.asset.s3_bucket_public == true
	msg := {
		"rule_id": "CIS-3.4.1",
		"issue": sprintf("CloudTrail trail '%v' uses S3 bucket '%v' that is publicly accessible", [input.asset.name, input.asset.s3_bucket]),
		"severity": "CRITICAL",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "3 Logging",
		"status": "FAIL",
		"compliance": ["CIS 3.4", "CERT-In 2022", "DPDP 2023"],
		"remediation": sprintf("aws s3api put-public-access-block --bucket %v --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", [input.asset.s3_bucket]),
	}
}

# ---------------------------------------------------------------------------
# CloudWatch Logs integration
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	not input.asset.cloudwatch_logs_enabled
	msg := {
		"rule_id": "CIS-3.5.1",
		"issue": sprintf("CloudTrail trail '%v' is not integrated with CloudWatch Logs", [input.asset.name]),
		"severity": "LOW",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "3 Logging",
		"status": "FAIL",
		"compliance": ["CIS 3.5", "CERT-In 2022"],
		"remediation": sprintf("aws cloudtrail update-trail --name %v --cloud-watch-logs-log-group-arn <log_group_arn> --cloud-watch-logs-role-arn <role_arn>", [input.asset.name]),
	}
}
