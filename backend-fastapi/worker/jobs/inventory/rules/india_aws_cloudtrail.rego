# CloudSecure India compliance — CloudTrail (CERT-In 2022, DPDP 2023)
# CERT-In 2022 mandates logging and monitoring; DPDP requires security measures.

package cloudsecure.rules.india_aws_cloudtrail

import rego.v1

default allow := true

# ---------------------------------------------------------------------------
# CERT-In 2022: Multi-region trail with logging
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	not input.asset.is_multi_region
	msg := {
		"rule_id": "CERT-In-CT-MULTIREGION",
		"issue": sprintf("CloudTrail trail '%v' is not multi-region — CERT-In 2022 requires organisation-wide logging", [input.asset.name]),
		"severity": "HIGH",
		"framework": "CERT-In 2022",
		"section": "Logging and Monitoring",
		"status": "FAIL",
		"compliance": ["CERT-In 2022", "DPDP 2023"],
		"remediation": sprintf("aws cloudtrail update-trail --name %v --is-multi-region-trail", [input.asset.name]),
	}
}

deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	not input.asset.is_logging
	msg := {
		"rule_id": "CERT-In-CT-LOGGING",
		"issue": sprintf("CloudTrail trail '%v' is not logging — CERT-In 2022 mandates continuous audit logging", [input.asset.name]),
		"severity": "CRITICAL",
		"framework": "CERT-In 2022",
		"section": "Logging and Monitoring",
		"status": "FAIL",
		"compliance": ["CERT-In 2022", "DPDP 2023 S.8"],
		"remediation": sprintf("aws cloudtrail start-logging --name %v", [input.asset.name]),
	}
}

# ---------------------------------------------------------------------------
# CERT-In: Log file validation
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	not input.asset.log_file_validation_enabled
	msg := {
		"rule_id": "CERT-In-CT-VALIDATION",
		"issue": sprintf("CloudTrail trail '%v' does not have log file validation — CERT-In recommends integrity of logs", [input.asset.name]),
		"severity": "MEDIUM",
		"framework": "CERT-In 2022",
		"section": "Logging and Monitoring",
		"status": "FAIL",
		"compliance": ["CERT-In 2022"],
		"remediation": sprintf("aws cloudtrail update-trail --name %v --enable-log-file-validation", [input.asset.name]),
	}
}

# ---------------------------------------------------------------------------
# DPDP / CERT-In: KMS encryption for logs
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	not input.asset.kms_encryption_enabled
	msg := {
		"rule_id": "DPDP-CT-KMS",
		"issue": sprintf("CloudTrail trail '%v' logs are not encrypted with KMS — DPDP and CERT-In recommend encryption of audit data", [input.asset.name]),
		"severity": "MEDIUM",
		"framework": "DPDP Act 2023",
		"section": "Section 8 - Security",
		"status": "FAIL",
		"compliance": ["DPDP 2023 S.8", "CERT-In 2022", "RBI"],
		"remediation": sprintf("aws cloudtrail update-trail --name %v --kms-key-id <kms_key_arn>", [input.asset.name]),
	}
}

# ---------------------------------------------------------------------------
# S3 bucket for trail publicly accessible
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	input.asset.s3_bucket_public == true
	msg := {
		"rule_id": "CERT-In-CT-S3-PUBLIC",
		"issue": sprintf("CloudTrail trail '%v' uses a publicly accessible S3 bucket '%v' — CERT-In requires protecting audit logs", [input.asset.name, input.asset.s3_bucket]),
		"severity": "CRITICAL",
		"framework": "CERT-In 2022",
		"section": "Logging and Monitoring",
		"status": "FAIL",
		"compliance": ["CERT-In 2022", "DPDP 2023"],
		"remediation": sprintf("Enable Block Public Access on the CloudTrail S3 bucket: aws s3api put-public-access-block --bucket %v --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", [input.asset.s3_bucket]),
	}
}
