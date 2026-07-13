# CloudSecure India compliance — IAM (DPDP 2023, CERT-In 2022, RBI)
# Same resource types as cis_aws_iam; India-specific mappings.

package cloudsecure.rules.india_aws_iam

import rego.v1

default allow := true

# ---------------------------------------------------------------------------
# CERT-In 2022: MFA for console users
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "iam_user"
	input.asset.has_console_password
	not input.asset.mfa_enabled
	msg := {
		"rule_id": "CERT-In-IAM-MFA",
		"issue": sprintf("IAM user '%v' has console access without MFA — CERT-In 2022 requires multi-factor authentication", [input.asset.user_name]),
		"severity": "HIGH",
		"framework": "CERT-In 2022",
		"section": "Identity and Access Management",
		"status": "FAIL",
		"compliance": ["CERT-In 2022", "DPDP 2023", "RBI"],
		"remediation": "Enable MFA for the user in IAM console or remove console password; prefer hardware MFA for privileged users",
	}
}

# ---------------------------------------------------------------------------
# DPDP: Role assumption without MFA for sensitive roles
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "iam_role"
	not input.asset.requires_mfa
	input.asset.role_sensitive
	msg := {
		"rule_id": "DPDP-IAM-ROLE-MFA",
		"issue": sprintf("IAM role '%v' can be assumed without MFA — DPDP Section 8 requires security measures for sensitive access", [input.asset.role_name]),
		"severity": "HIGH",
		"framework": "DPDP Act 2023",
		"section": "Section 8 - Security",
		"status": "FAIL",
		"compliance": ["DPDP 2023 S.8", "CERT-In 2022", "RBI"],
		"remediation": "Add Condition to assume role policy requiring aws:MultiFactorAuthPresent",
	}
}

# ---------------------------------------------------------------------------
# CERT-In: Overly permissive trust policy
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "iam_role"
	input.asset.trust_policy_public_or_cross_account
	msg := {
		"rule_id": "CERT-In-IAM-TRUST",
		"issue": sprintf("IAM role '%v' has trust policy allowing unrestricted or cross-account assumption — CERT-In requires least privilege", [input.asset.role_name]),
		"severity": "HIGH",
		"framework": "CERT-In 2022",
		"section": "Identity and Access Management",
		"status": "FAIL",
		"compliance": ["CERT-In 2022", "RBI"],
		"remediation": "Restrict Principal to specific account/role and add aws:SourceAccount/aws:SourceArn conditions where applicable",
	}
}
