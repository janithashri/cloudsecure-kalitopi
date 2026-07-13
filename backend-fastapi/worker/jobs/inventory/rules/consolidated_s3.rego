# CloudSecure consolidated S3 public access rule
# Reproduces "Precision over Noise" (arXiv 2508.14402) 5-condition logic.
# Replaces fragmented CIS-2.1.x, DPDP-S3-*, CERT-In-S3-*, RBI-S3-* public-access rules.

package cloudsecure.rules.consolidated_s3

import rego.v1

# =================================================================
# CONSOLIDATED-S3-001: S3 Public Access Validation and Data Exposure
# =================================================================

deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	condition_1_public_acl_grants
	msg := build_msg("public_acl_grants")
}

deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	condition_2_public_policy_and_facing
	msg := build_msg("public_policy_and_exposure_facing")
}

deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	condition_3_facing_bpa_disabled_risky_actions
	msg := build_msg("public_facing_bpa_disabled_risky_actions")
}

deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	condition_4_any_public_allow_bpa_disabled
	msg := build_msg("public_allow_policy_bpa_disabled")
}

deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	condition_5_facing_sensitive_data
	msg := build_msg("public_facing_sensitive_data")
}

# --- Condition 1: Public ACL grants (AuthenticatedUsers or AllUsers+READ) ---
condition_1_public_acl_grants if {
	some grant in input.asset.acl_grants
	contains(grant.grantee_uri, "global/AuthenticatedUsers")
}

condition_1_public_acl_grants if {
	some grant in input.asset.acl_grants
	contains(grant.grantee_uri, "global/AllUsers")
	grant.permission == "READ"
}

# --- Condition 2: Policy marked public AND exposure is public-facing ---
condition_2_public_policy_and_facing if {
	input.asset.policy_status_public == true
	input.asset.exposure == "public_facing"
}

# --- Condition 3: Public-facing + BPA.RestrictPublicBuckets disabled + risky action allowed ---
condition_3_facing_bpa_disabled_risky_actions if {
	input.asset.exposure == "public_facing"
	input.asset.public_access_block.restrict_public_buckets == false
	some stmt in input.asset.bucket_policy_statements
	stmt.effect == "Allow"
	risky_action(stmt.action)
	contains(stmt.principal_aws, "*")
	not stmt.restricted_access_condition
}

risky_action(a) if {
	contains(a, "s3:GetObject")
}

risky_action(a) if {
	contains(a, "s3:ListBucket")
}

risky_action(a) if {
	contains(a, "s3:PutObjectAcl")
}

risky_action(a) if {
	contains(a, "s3:DeleteObject")
}

risky_action(a) if {
	contains(a, "s3:GetBucketAcl")
}

risky_action(a) if {
	contains(a, "s3:PutBucketAcl")
}

# --- Condition 4: Any public Allow policy + BPA disabled (no risky-action filter) ---
condition_4_any_public_allow_bpa_disabled if {
	input.asset.public_access_block.restrict_public_buckets == false
	some stmt in input.asset.bucket_policy_statements
	stmt.effect == "Allow"
	contains(stmt.principal_aws, "*")
	not stmt.restricted_access_condition
}

# --- Condition 5: Public-facing + tagged sensitive data ---
condition_5_facing_sensitive_data if {
	input.asset.exposure == "public_facing"
	input.asset.sensitive_data == true
}

build_msg(matched_condition) := msg if {
	msg := {
		"rule_id": "CONSOLIDATED-S3-001",
		"issue": sprintf("S3 bucket '%v' flagged: %v", [input.asset.bucket_name, matched_condition]),
		"matched_condition": matched_condition,
		"severity": "CRITICAL",
		"framework": "CIS 2.1.x + DPDP 2023 + CERT-In 2022 + RBI (consolidated)",
		"compliance": ["CIS 2.1.x", "DPDP 2023", "CERT-In 2022", "RBI"],
		"remediation": "Enable all 4 Block Public Access settings; remove wildcard Principal in bucket policy unless restricted by a Condition block",
	}
}
