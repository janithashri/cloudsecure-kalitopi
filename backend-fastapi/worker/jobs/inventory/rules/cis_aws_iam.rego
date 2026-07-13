# CloudSecure CIS AWS Foundations Benchmark — IAM (Users & Roles)
# Prowler reference: providers/aws/services/iam/
# Input: input.asset (asset_type: "iam_user" or "iam_role")

package cloudsecure.rules.cis_aws_iam

import rego.v1

default allow := true

# ---------------------------------------------------------------------------
# CIS 1.10: IAM user with console password must have MFA
# Real-world impact: Account takeover via stolen or phished passwords; MFA drastically reduces risk.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "iam_user"
	input.asset.has_console_password
	not input.asset.mfa_enabled
	msg := {
		"rule_id": "CIS-1.10",
		"issue": sprintf("IAM user '%v' has console password enabled but MFA is not enabled", [input.asset.user_name]),
		"severity": severity_mfa,
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "1 Identity and Access Management",
		"status": "FAIL",
		"compliance": ["CIS 1.10", "CERT-In 2022"],
		"remediation": sprintf("Enable MFA in AWS Console: IAM > Users > %v > Security credentials > Assign MFA device. Or remove console password: aws iam delete-login-profile --user-name %v", [input.asset.user_name, input.asset.user_name]),
	}
}

severity_mfa := "HIGH" if {
	input.asset.tags.admin == "true"
} else := "MEDIUM"

# ---------------------------------------------------------------------------
# CIS 1.15: Permissions only through groups (no inline or direct attach on user)
# INGESTION GAP: fetcher may not expose attached managed policies; use inline_policies only for now.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "iam_user"
	count(input.asset.inline_policy_names) > 0
	msg := {
		"rule_id": "CIS-1.15",
		"issue": sprintf("IAM user '%v' has inline policies — permissions should be granted only through groups", [input.asset.user_name]),
		"severity": "LOW",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "1 Identity and Access Management",
		"status": "FAIL",
		"compliance": ["CIS 1.15"],
		"remediation": "Move permissions to an IAM group and add the user to the group; remove inline policies from the user",
	}
}

# ---------------------------------------------------------------------------
# CIS 1.16: Role trust policy should require MFA for sensitive roles
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "iam_role"
	not input.asset.requires_mfa
	input.asset.role_sensitive
	msg := {
		"rule_id": "CIS-1.16",
		"issue": sprintf("IAM role '%v' can be assumed without MFA — require aws:MultiFactorAuthPresent in trust policy for sensitive roles", [input.asset.role_name]),
		"severity": "HIGH",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "1 Identity and Access Management",
		"status": "FAIL",
		"compliance": ["CIS 1.16", "CERT-In 2022"],
		"remediation": "Add Condition to assume role policy: {\"Condition\":{\"Bool\":{\"aws:MultiFactorAuthPresent\":\"true\"}}}",
	}
}

# ---------------------------------------------------------------------------
# Role: overly permissive trust (Principal "*" or other account without condition)
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "iam_role"
	input.asset.trust_policy_public_or_cross_account
	msg := {
		"rule_id": "CIS-1.20",
		"issue": sprintf("IAM role '%v' has trust policy that allows public or unrestricted cross-account assumption", [input.asset.role_name]),
		"severity": "HIGH",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "1 Identity and Access Management",
		"status": "FAIL",
		"compliance": ["CIS 1.20", "CERT-In 2022"],
		"remediation": "Restrict Principal in assume role policy to specific account and optionally add aws:SourceAccount condition",
	}
}
