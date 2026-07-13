# CloudSecure CIS AWS Foundations Benchmark — KMS
# Prowler reference: providers/aws/services/kms/
# Input: input.asset (asset_type: "kms_key")

package cloudsecure.rules.cis_aws_kms

import rego.v1

default allow := true

# ---------------------------------------------------------------------------
# KMS key policy must not allow public or cross-account access
# Real-world impact: Keys with Principal "*" allow any AWS principal to use the key.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "kms_key"
	input.asset.key_policy_public_or_external
	msg := {
		"rule_id": "CIS-3.1.1",
		"issue": sprintf("KMS key '%v' in region '%v' has a policy that allows public or external account access", [input.asset.key_id, input.asset.region]),
		"severity": "CRITICAL",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "3 Logging",
		"status": "FAIL",
		"compliance": ["CIS 3.1", "DPDP 2023", "CERT-In 2022", "RBI"],
		"remediation": sprintf("aws kms put-key-policy --key-id %v --policy-name default --policy '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::<account_id>:root\"},\"Action\":\"kms:*\",\"Resource\":\"*\"}]}'", [input.asset.key_id]),
	}
}

# ---------------------------------------------------------------------------
# Customer managed key (CMK) rotation
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "kms_key"
	input.asset.key_manager == "CUSTOMER"
	input.asset.key_state == "Enabled"
	not input.asset.rotation_enabled
	msg := {
		"rule_id": "CIS-3.2.1",
		"issue": sprintf("KMS customer managed key '%v' does not have automatic key rotation enabled", [input.asset.key_id]),
		"severity": "HIGH",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "3 Logging",
		"status": "FAIL",
		"compliance": ["CIS 3.2", "RBI", "CERT-In 2022"],
		"remediation": sprintf("aws kms enable-key-rotation --key-id %v", [input.asset.key_id]),
	}
}

# ---------------------------------------------------------------------------
# KMS key pending deletion
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "kms_key"
	input.asset.key_state == "PendingDeletion"
	msg := {
		"rule_id": "CIS-3.3.1",
		"issue": sprintf("KMS key '%v' is in PendingDeletion state — cancel if deletion was unintended", [input.asset.key_id]),
		"severity": "CRITICAL",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "3 Logging",
		"status": "FAIL",
		"compliance": ["CIS 3.3", "DPDP 2023", "RBI"],
		"remediation": sprintf("aws kms cancel-key-deletion --key-id %v", [input.asset.key_id]),
	}
}

# ---------------------------------------------------------------------------
# Prefer single-region CMK (optional — multi-region keys replicate and can expand blast radius)
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "kms_key"
	input.asset.multi_region == true
	msg := {
		"rule_id": "CIS-3.4.1",
		"issue": sprintf("KMS key '%v' is a multi-region key — consider single-region for tighter control", [input.asset.key_id]),
		"severity": "MEDIUM",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "3 Logging",
		"status": "FAIL",
		"compliance": ["CIS 3.4", "CERT-In 2022"],
		"remediation": "Create a new single-region CMK and migrate usage; multi-region key settings cannot be changed after creation",
	}
}
