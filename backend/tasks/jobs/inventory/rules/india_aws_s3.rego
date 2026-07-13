# CloudSecure India compliance — S3 (DPDP 2023, CERT-In 2022, RBI)
# Same resource type as cis_aws_s3; India-specific mappings and rationale.

package cloudsecure.rules.india_aws_s3

import rego.v1

default allow := true

# ---------------------------------------------------------------------------
# DPDP Section 8: Block public access (data protection)
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	not block_public_fully_enabled
	msg := {
		"rule_id": "DPDP-S3-PUBLIC",
		"issue": sprintf("S3 bucket '%v' does not have all Block Public Access settings enabled — DPDP 2023 requires protecting personal data", [input.asset.bucket_name]),
		"severity": severity_india_public,
		"framework": "DPDP Act 2023",
		"section": "Section 8 - Security",
		"status": "FAIL",
		"compliance": ["DPDP 2023 S.8", "CERT-In 2022", "RBI"],
		"remediation": sprintf("aws s3api put-public-access-block --bucket %v --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", [input.asset.bucket_name]),
	}
}

block_public_fully_enabled if {
	input.asset.block_public_acls == true
	input.asset.ignore_public_acls == true
	input.asset.block_public_policy == true
	input.asset.restrict_public_buckets == true
}

severity_india_public := "CRITICAL" if {
	input.asset.tags.environment == "production"
} else := "HIGH"

# ---------------------------------------------------------------------------
# CERT-In 2022: Default encryption
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	not input.asset.server_side_encryption_enabled
	msg := {
		"rule_id": "CERT-In-S3-ENCRYPT",
		"issue": sprintf("S3 bucket '%v' does not have default server-side encryption — CERT-In 2022 recommends encryption of data at rest", [input.asset.bucket_name]),
		"severity": "HIGH",
		"framework": "CERT-In 2022",
		"section": "Data Protection",
		"status": "FAIL",
		"compliance": ["CERT-In 2022", "DPDP 2023", "RBI"],
		"remediation": sprintf("aws s3api put-bucket-encryption --bucket %v --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'", [input.asset.bucket_name]),
	}
}

# ---------------------------------------------------------------------------
# CERT-In: Access logging for audit trail
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	not input.asset.access_logging_enabled
	msg := {
		"rule_id": "CERT-In-S3-LOGGING",
		"issue": sprintf("S3 bucket '%v' does not have server access logging — CERT-In 2022 requires audit logging", [input.asset.bucket_name]),
		"severity": "MEDIUM",
		"framework": "CERT-In 2022",
		"section": "Logging and Monitoring",
		"status": "FAIL",
		"compliance": ["CERT-In 2022", "DPDP 2023"],
		"remediation": sprintf("aws s3api put-bucket-logging --bucket %v --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"<LOG_BUCKET>\",\"TargetPrefix\":\"logs/\"}}'", [input.asset.bucket_name]),
	}
}

# ---------------------------------------------------------------------------
# RBI / DPDP: Cross-account policy
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	input.asset.has_cross_account_policy
	msg := {
		"rule_id": "RBI-S3-CROSS-ACCOUNT",
		"issue": sprintf("S3 bucket '%v' has a policy granting cross-account or public access — RBI and DPDP require controlled data sharing", [input.asset.bucket_name]),
		"severity": "HIGH",
		"framework": "RBI Cyber Security Framework",
		"section": "Access Control",
		"status": "FAIL",
		"compliance": ["RBI", "DPDP 2023", "CERT-In 2022"],
		"remediation": "Restrict bucket policy Principal to same account or explicit role ARNs; remove Principal \"*\"",
	}
}

# ---------------------------------------------------------------------------
# Public access (compound)
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	input.asset.is_public
	msg := {
		"rule_id": "DPDP-S3-IS-PUBLIC",
		"issue": sprintf("S3 bucket '%v' has public access — Block Public Access is not fully enabled or bucket has public ACL/policy", [input.asset.bucket_name]),
		"severity": "CRITICAL",
		"framework": "DPDP Act 2023",
		"section": "Section 8 - Security",
		"status": "FAIL",
		"compliance": ["DPDP 2023 S.8", "CERT-In 2022", "RBI"],
		"remediation": "Enable Block Public Access on the bucket and remove any public ACL or policy grants",
	}
}
