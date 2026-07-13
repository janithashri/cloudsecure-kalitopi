# CloudSecure CIS AWS Foundations Benchmark — S3 Buckets
# Prowler reference: providers/aws/services/s3/
# Input: input.asset (built from fetcher output); asset_type must be "s3_bucket"

package cloudsecure.rules.cis_aws_s3

import rego.v1

default allow := true

# ---------------------------------------------------------------------------
# CIS 2.1.1 / 2.1.4 — Block Public Access (bucket-level)
# Real-world impact: Public S3 buckets are the #1 cause of AWS data breaches
# (e.g. Capital One 2019). Block Public Access prevents accidental public ACLs/policies.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	not block_public_fully_enabled
	msg := {
		"rule_id": "CIS-2.1.4",
		"issue": sprintf("S3 bucket '%v' in region '%v' does not have all Block Public Access settings enabled — risk of public exposure", [input.asset.bucket_name, input.asset.region]),
		"severity": severity_bucket_public,
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "2 Storage Services – S3",
		"status": "FAIL",
		"compliance": ["CIS 2.1.4", "CIS 2.1.1", "DPDP 2023 S.8", "CERT-In 2022"],
		"remediation": sprintf("Enable Block Public Access: aws s3api put-public-access-block --bucket %v --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", [input.asset.bucket_name]),
	}
}

block_public_fully_enabled if {
	input.asset.block_public_acls == true
	input.asset.ignore_public_acls == true
	input.asset.block_public_policy == true
	input.asset.restrict_public_buckets == true
}

severity_bucket_public := "CRITICAL" if {
	input.asset.tags.environment == "production"
} else := "HIGH"

# ---------------------------------------------------------------------------
# CIS 2.1.1 — Secure transport (HTTPS only)
# Real-world impact: HTTP allows eavesdropping and token theft; pre-signed URLs can be replayed.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	not input.asset.secure_transport_policy
	msg := {
		"rule_id": "CIS-2.1.1",
		"issue": sprintf("S3 bucket '%v' does not enforce HTTPS — bucket policy should deny requests when aws:SecureTransport is false", [input.asset.bucket_name]),
		"severity": "MEDIUM",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "2 Storage Services – S3",
		"status": "FAIL",
		"compliance": ["CIS 2.1.1", "DPDP 2023", "CERT-In 2022"],
		"remediation": sprintf("aws s3api put-bucket-policy --bucket %v --policy '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::%v/*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}'", [input.asset.bucket_name, input.asset.bucket_name]),
	}
}

# ---------------------------------------------------------------------------
# CIS 2.1.2 — MFA Delete (optional for versioned buckets)
# INGESTION GAP: field 'mfa_delete_enabled' not yet in S3 fetcher (versioning returns Status only).
# Rule fires when fetcher provides mfa_delete_enabled and it is false.
# Enhancement needed in: tasks/jobs/inventory/fetchers/s3.py (get_bucket_versioning returns MfaDelete).
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	input.asset.versioning_enabled == true
	input.asset.mfa_delete_enabled == false
	msg := {
		"rule_id": "CIS-2.1.2",
		"issue": sprintf("S3 bucket '%v' has versioning enabled but MFA Delete is not enabled — permanent deletes do not require MFA", [input.asset.bucket_name]),
		"severity": "MEDIUM",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "2 Storage Services – S3",
		"status": "FAIL",
		"compliance": ["CIS 2.1.2", "CERT-In 2022"],
		"remediation": sprintf("Enable MFA Delete (root only): aws s3api put-bucket-versioning --bucket %v --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa \"<MFA_SERIAL> <MFA_CODE>\"", [input.asset.bucket_name]),
	}
}

# ---------------------------------------------------------------------------
# CIS 2.1.x — Server access logging
# Real-world impact: Without logging, exfiltration and policy changes are hard to detect.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	not input.asset.access_logging_enabled
	msg := {
		"rule_id": "CIS-2.1.5",
		"issue": sprintf("S3 bucket '%v' in region '%v' does not have server access logging enabled", [input.asset.bucket_name, input.asset.region]),
		"severity": severity_logging,
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "2 Storage Services – S3",
		"status": "FAIL",
		"compliance": ["CIS 2.1.5", "CERT-In 2022", "DPDP 2023"],
		"remediation": sprintf("aws s3api put-bucket-logging --bucket %v --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"<LOG_BUCKET>\",\"TargetPrefix\":\"logs/\"}}'", [input.asset.bucket_name]),
	}
}

severity_logging := "HIGH" if {
	input.asset.is_public
} else := "MEDIUM"

# ---------------------------------------------------------------------------
# CIS 2.1.6 — Default encryption (SSE)
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	not input.asset.server_side_encryption_enabled
	msg := {
		"rule_id": "CIS-2.1.6",
		"issue": sprintf("S3 bucket '%v' does not have default server-side encryption enabled", [input.asset.bucket_name]),
		"severity": severity_encryption,
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "2 Storage Services – S3",
		"status": "FAIL",
		"compliance": ["CIS 2.1.6", "DPDP 2023", "RBI", "CERT-In 2022"],
		"remediation": sprintf("aws s3api put-bucket-encryption --bucket %v --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'", [input.asset.bucket_name]),
	}
}

severity_encryption := "HIGH" if {
	input.asset.tags.data_classification == "confidential"
} else := "MEDIUM"

# ---------------------------------------------------------------------------
# Object versioning — recovery and integrity
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	not input.asset.versioning_enabled
	msg := {
		"rule_id": "CIS-2.1.7",
		"issue": sprintf("S3 bucket '%v' does not have object versioning enabled — overwrites and deletes are irreversible", [input.asset.bucket_name]),
		"severity": "MEDIUM",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "2 Storage Services – S3",
		"status": "FAIL",
		"compliance": ["CIS 2.1.7", "DPDP 2023"],
		"remediation": sprintf("aws s3api put-bucket-versioning --bucket %v --versioning-configuration Status=Enabled", [input.asset.bucket_name]),
	}
}

# ---------------------------------------------------------------------------
# Public access (compound: any block setting false or public ACL/policy)
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	input.asset.is_public
	msg := {
		"rule_id": "CIS-2.1.4-PUBLIC",
		"issue": sprintf("S3 bucket '%v' in region '%v' has public access — Block Public Access is not fully enabled or bucket has public ACL/policy", [input.asset.bucket_name, input.asset.region]),
		"severity": severity_public,
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "2 Storage Services – S3",
		"status": "FAIL",
		"compliance": ["CIS 2.1.4", "DPDP 2023 S.8", "CERT-In 2022"],
		"remediation": sprintf("Enable Block Public Access: aws s3api put-public-access-block --bucket %v --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", [input.asset.bucket_name]),
	}
}

severity_public := "CRITICAL" if {
	input.asset.tags.environment == "production"
} else := "HIGH"

# ---------------------------------------------------------------------------
# Cross-account policy — restrict to same account unless intended
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	input.asset.has_cross_account_policy
	msg := {
		"rule_id": "CIS-2.1-CROSS-ACCOUNT",
		"issue": sprintf("S3 bucket '%v' has a bucket policy that grants access to other accounts or Principal '*' — reduce scope to same account or explicit principals", [input.asset.bucket_name]),
		"severity": "HIGH",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "2 Storage Services – S3",
		"status": "FAIL",
		"compliance": ["CIS", "CERT-In 2022", "DPDP 2023"],
		"remediation": "Review and edit bucket policy: restrict Principal to arn:aws:iam::<account-id>:root or specific role ARNs; avoid Principal \"*\"",
	}
}

# ---------------------------------------------------------------------------
# Prefer KMS for sensitive data (optional / informational)
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	input.asset.server_side_encryption_enabled
	input.asset.encryption_type != "aws:kms"
	input.asset.encryption_type != "aws:kms:dsse"
	input.asset.tags.data_classification == "confidential"
	msg := {
		"rule_id": "CIS-2.1.6-KMS",
		"issue": sprintf("S3 bucket '%v' with confidential data uses SSE-S3 instead of SSE-KMS — prefer KMS for key control and audit", [input.asset.bucket_name]),
		"severity": "MEDIUM",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "2 Storage Services – S3",
		"status": "FAIL",
		"compliance": ["CIS 2.1.6", "RBI", "DPDP 2023"],
		"remediation": sprintf("aws s3api put-bucket-encryption --bucket %v --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'", [input.asset.bucket_name]),
	}
}
