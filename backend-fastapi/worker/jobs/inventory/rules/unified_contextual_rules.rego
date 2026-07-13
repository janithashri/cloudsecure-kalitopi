# CloudSecure — Unified contextual Rego rules (conjunctive, multi-signal)
#
# Design: a finding fires only when ALL signals inside a condition block are true
# AND no compensating control exists. Single-condition checks must NOT fire here.
#
# Top-level condition blocks are OR'd; signals inside each block are AND'd.
#
# Input shape: {"input": {"asset": {...}, "account": {...} (optional)}}
#
# Uses existing input_builder fields where available. Optional enriched fields
# (documented below) enable full cross-resource context when added to input_builder.
#
# Optional input.asset enrichments (future input_builder):
#   S3: policy, acl_grants, is_internet_facing
#   EC2: security_group_allows_ssh_from_internet, security_group_allows_rdp_from_internet,
#        stopped_days, has_unencrypted_ebs_volume, has_attached_ebs_volume
#   IAM user: last_login_within_days, access_key_age_days, access_key_used_within_days,
#        has_administrator_access, has_permission_boundary, scp_protected
#   IAM role: trust_allows_any_principal, trust_has_restriction_condition,
#        has_administrator_access, has_permission_boundary
#   RDS: db_port_exposed_from_internet, engine (mysql/postgres/mssql/oracle)
#   KMS: key_age_days, policy_allows_wildcard_decrypt, policy_has_service_condition,
#        is_default_service_key
#   CloudTrail: logging_gap_hours, trail_created_at, last_log_delivery_at,
#        is_only_trail_in_account
#   Security group: attached_to_running_instance, attached_instance_has_public_ip,
#        attached_instance_iam_data_access, intentionally_open
#
# Optional input.account enrichments:
#   organisation_trail_exists, multi_region_resources, trail_count

package cloudsecure.rules.unified_contextual

import rego.v1

default allow := true

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

tags := object.get(input.asset, "tags", {})

account_ctx := object.get(input, "account", {})

# Sensitive / production amplifiers
sensitive_data_present if {
	lower(object.get(tags, "data_classification", "")) in {"confidential", "sensitive", "pii", "restricted"}
}

sensitive_data_present if {
	lower(object.get(tags, "data", "")) in {"pii", "sensitive", "confidential"}
}

sensitive_data_present if {
	lower(object.get(tags, "contains_sensitive_data", "")) in {"true", "yes", "1"}
}

production_resource if {
	lower(object.get(tags, "environment", "")) in {"production", "prod"}
}

ssm_managed_access if {
	lower(object.get(tags, "ssm_managed", "")) in {"true", "yes", "1"}
}

ssm_managed_access if {
	lower(object.get(tags, "access", "")) == "ssm-session-manager"
}

intentionally_open_exposure if {
	lower(object.get(tags, "exposure", "")) == "intentional"
}

# Compensating control: restrictive policy/trust condition present
restricted_access_condition(policy) if {
	some st in policy.Statement
	cond := object.get(st, "Condition", {})
	object.keys(cond) != []
}

restricted_access_condition(policy) if {
	some st in policy.Statement
	cond := object.get(st, "Condition", {})
	ip := object.get(cond, "IpAddress", {})
	object.keys(ip) != []
}

restricted_access_condition(policy) if {
	some st in policy.Statement
	cond := object.get(st, "Condition", {})
	vpc := object.get(cond, "StringEquals", {})
	object.get(vpc, "aws:SourceVpc", "") != ""
}

restricted_access_condition(policy) if {
	some st in policy.Statement
	cond := object.get(st, "Condition", {})
	org := object.get(cond, "StringEquals", {})
	object.get(org, "aws:PrincipalOrgID", "") != ""
}

restricted_access_condition(policy) if {
	some st in policy.Statement
	cond := object.get(st, "Condition", {})
	vpce := object.get(cond, "StringEquals", {})
	object.get(vpce, "aws:SourceVpce", "") != ""
}

no_restricting_condition if {
	not "policy" in input.asset
}

no_restricting_condition if {
	policy := input.asset.policy
	not restricted_access_condition(policy)
}

# Wildcard principal Allow (not Deny)
policy_has_wildcard_allow if {
	policy := input.asset.policy
	some st in policy.Statement
	st.Effect == "Allow"
	principal := st.Principal
	principal == "*"
}

policy_has_wildcard_allow if {
	policy := input.asset.policy
	some st in policy.Statement
	st.Effect == "Allow"
	principal := st.Principal
	principal.AWS == "*"
}

# S3 dangerous object/bucket actions
s3_dangerous_action(action) if {
	action in {"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:PutObjectAcl", "s3:*"}
}

policy_allows_dangerous_s3_actions if {
	policy := input.asset.policy
	some st in policy.Statement
	st.Effect == "Allow"
	some act in object.get(st, "Action", [])
	s3_dangerous_action(act)
}

policy_allows_dangerous_s3_actions if {
	policy := input.asset.policy
	some st in policy.Statement
	st.Effect == "Allow"
	act := st.Action
	s3_dangerous_action(act)
}

# Global ACL grants to AllUsers / AuthenticatedUsers with read or write
s3_global_acl_read_or_write if {
	some grant in input.asset.acl_grants
	grantee := grant.grantee
	grantee in {
		"http://acs.amazonaws.com/groups/global/AllUsers",
		"http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
	}
	grant.permission in {"READ", "WRITE", "FULL_CONTROL"}
}

s3_bpa_restrict_public_buckets_disabled if {
	input.asset.restrict_public_buckets == false
}

s3_internet_facing if {
	input.asset.is_internet_facing == true
}

s3_internet_facing if {
	input.asset.is_public == true
}

# ---------------------------------------------------------------------------
# 1. S3 — unified public exposure (OR of AND blocks)
# ---------------------------------------------------------------------------

deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	s3_global_acl_read_or_write
	no_restricting_condition
	msg := s3_unified_msg(
		"CTX-S3-ACL-PUBLIC",
		"CRITICAL",
		sprintf(
			"S3 bucket '%v' has global ACL grants (AllUsers/AuthenticatedUsers) with read/write permissions and no restricting bucket policy condition",
			[input.asset.bucket_name],
		),
		"Remove public ACL grants; enable Block Public Access; add aws:SourceVpc / IP / Org conditions if public access is required",
	)
}

deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	s3_internet_facing
	input.asset.is_public == true
	no_restricting_condition
	msg := s3_unified_msg(
		"CTX-S3-POLICY-PUBLIC-EXPOSED",
		"CRITICAL",
		sprintf(
			"S3 bucket '%v' is internet-facing with public policy/ACL exposure and no compensating access restriction",
			[input.asset.bucket_name],
		),
		"Enable full Block Public Access or restrict policy Principal and add Condition (IP, VPC, Org)",
	)
}

deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	s3_bpa_restrict_public_buckets_disabled
	policy_has_wildcard_allow
	policy_allows_dangerous_s3_actions
	no_restricting_condition
	msg := s3_unified_msg(
		"CTX-S3-BPA-WILDCARD-DANGEROUS",
		"CRITICAL",
		sprintf(
			"S3 bucket '%v' has RestrictPublicBuckets disabled, wildcard Allow on dangerous object actions, and no restriction condition",
			[input.asset.bucket_name],
		),
		"Enable RestrictPublicBuckets; remove Principal '*'; scope actions and add Condition",
	)
}

deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	policy_has_wildcard_allow
	s3_bpa_restrict_public_buckets_disabled
	no_restricting_condition
	msg := s3_unified_msg(
		"CTX-S3-WILDCARD-NO-BPA",
		"HIGH",
		sprintf(
			"S3 bucket '%v' allows wildcard principal with BPA RestrictPublicBuckets disabled and no restriction condition",
			[input.asset.bucket_name],
		),
		"Enable RestrictPublicBuckets and replace wildcard Principal with explicit principals plus Condition",
	)
}

deny contains msg if {
	input.asset.asset_type == "s3_bucket"
	s3_internet_facing
	sensitive_data_present
	no_restricting_condition
	msg := s3_unified_msg(
		"CTX-S3-SENSITIVE-EXPOSED",
		"CRITICAL",
		sprintf(
			"S3 bucket '%v' is internet-facing, tagged with sensitive data, and lacks restricting access conditions",
			[input.asset.bucket_name],
		),
		"Move sensitive data to private buckets; enforce BPA, encryption, and VPC/IP-bound policy conditions",
	)
}

s3_unified_msg(rule_id, severity, issue, remediation) := {
	"rule_id": rule_id,
	"issue": issue,
	"severity": severity,
	"framework": "CloudSecure Contextual Rules",
	"section": "S3 Unified Exposure",
	"status": "FAIL",
	"compliance": ["Contextual-Risk", "DPDP 2023 S.8", "CIS 2.1.4"],
	"remediation": remediation,
}

# ---------------------------------------------------------------------------
# 2. EC2 instances — unified high-risk exposure
# ---------------------------------------------------------------------------

deny contains msg if {
	input.asset.asset_type == "ec2_instance"
	input.asset.has_public_ip == true
	input.asset.security_group_allows_ssh_from_internet == true
	not ssm_managed_access
	msg := ec2_unified_msg(
		"CTX-EC2-PUBLIC-SSH",
		"HIGH",
		sprintf(
			"EC2 instance '%v' has public IP, security group allows SSH from internet, and no SSM Session Manager compensating control",
			[input.asset.instance_id],
		),
		"Remove public IP; restrict SG port 22; use SSM Session Manager (tag access=ssm-session-manager)",
	)
}

deny contains msg if {
	input.asset.asset_type == "ec2_instance"
	input.asset.has_public_ip == true
	input.asset.security_group_allows_rdp_from_internet == true
	not ssm_managed_access
	msg := ec2_unified_msg(
		"CTX-EC2-PUBLIC-RDP",
		"HIGH",
		sprintf(
			"EC2 instance '%v' has public IP, security group allows RDP from internet, and no SSM Session Manager compensating control",
			[input.asset.instance_id],
		),
		"Remove public IP; restrict SG port 3389; use SSM or VPN for admin access",
	)
}

deny contains msg if {
	input.asset.asset_type == "ec2_instance"
	not input.asset.imdsv2_required
	input.asset.iam_instance_profile_attached == true
	input.asset.has_public_ip == true
	msg := ec2_unified_msg(
		"CTX-EC2-IMDSV1-ROLE-EXPOSED",
		"CRITICAL",
		sprintf(
			"EC2 instance '%v' allows IMDSv1, has an IAM instance profile, and is internet-facing (public IP)",
			[input.asset.instance_id],
		),
		"Require IMDSv2 (HttpTokens=required) and remove public IP where possible",
	)
}

deny contains msg if {
	input.asset.asset_type == "ec2_instance"
	object.get(input.asset, "state", "") == "stopped"
	object.get(input.asset, "stopped_days", 0) > 90
	input.asset.has_attached_ebs_volume == true
	input.asset.has_unencrypted_ebs_volume == true
	msg := ec2_unified_msg(
		"CTX-EC2-STALE-UNENCRYPTED-EBS",
		"MEDIUM",
		sprintf(
			"EC2 instance '%v' stopped >90 days with attached unencrypted EBS volume — stale cost and data-at-rest risk",
			[input.asset.instance_id],
		),
		"Snapshot and terminate unused instances; encrypt EBS volumes or delete orphaned volumes",
	)
}

ec2_unified_msg(rule_id, severity, issue, remediation) := {
	"rule_id": rule_id,
	"issue": issue,
	"severity": severity,
	"framework": "CloudSecure Contextual Rules",
	"section": "EC2 Unified Exposure",
	"status": "FAIL",
	"compliance": ["Contextual-Risk", "CIS 4.1", "CERT-In 2022"],
	"remediation": remediation,
}

# ---------------------------------------------------------------------------
# 3. IAM users and roles — unified privilege risk
# ---------------------------------------------------------------------------

deny contains msg if {
	input.asset.asset_type == "iam_user"
	input.asset.has_console_password == true
	input.asset.mfa_enabled == false
	object.get(input.asset, "last_login_within_days", 999) <= 90
	msg := iam_unified_msg(
		"CTX-IAM-CONSOLE-NO-MFA-ACTIVE",
		"HIGH",
		sprintf(
			"IAM user '%v' has console access without MFA and logged in within the last 90 days",
			[input.asset.user_name],
		),
		"Enable MFA for active console users or remove console password",
	)
}

deny contains msg if {
	input.asset.asset_type in {"iam_user", "iam_role"}
	input.asset.has_administrator_access == true
	input.asset.has_permission_boundary == false
	object.get(input.asset, "scp_protected", false) == false
	name := object.get(input.asset, "user_name", object.get(input.asset, "role_name", ""))
	msg := iam_unified_msg(
		"CTX-IAM-ADMIN-NO-GUARDRAIL",
		"CRITICAL",
		sprintf(
			"IAM entity '%v' has AdministratorAccess (or *:* policy) without permission boundary or SCP protection",
			[name],
		),
		"Apply permission boundary; remove AdministratorAccess; enforce SCP at org level",
	)
}

deny contains msg if {
	input.asset.asset_type == "iam_user"
	object.get(input.asset, "access_key_exists", false) == true
	object.get(input.asset, "access_key_age_days", 0) > 90
	object.get(input.asset, "access_key_used_within_days", 999) <= 30
	msg := iam_unified_msg(
		"CTX-IAM-STALE-ACTIVE-KEY",
		"MEDIUM",
		sprintf(
			"IAM user '%v' has an access key older than 90 days that was used in the last 30 days — rotate stale active credentials",
			[input.asset.user_name],
		),
		"Rotate access keys; prefer IAM roles and short-lived credentials",
	)
}

deny contains msg if {
	input.asset.asset_type == "iam_role"
	input.asset.trust_allows_any_principal == true
	input.asset.trust_has_restriction_condition == false
	msg := iam_unified_msg(
		"CTX-IAM-TRUST-WILDCARD",
		"CRITICAL",
		sprintf(
			"IAM role '%v' trust policy allows AssumeRole from any principal without ExternalId, MFA, or IP condition",
			[input.asset.role_name],
		),
		"Restrict Principal to specific account/role; add aws:SourceAccount, ExternalId, or MFA condition",
	)
}

# Fallback using existing flattened trust flag when enriched fields absent
deny contains msg if {
	input.asset.asset_type == "iam_role"
	input.asset.trust_policy_public_or_cross_account == true
	not input.asset.requires_mfa
	not "trust_has_restriction_condition" in input.asset
	msg := iam_unified_msg(
		"CTX-IAM-TRUST-UNRESTRICTED",
		"HIGH",
		sprintf(
			"IAM role '%v' has unrestricted cross-account/public trust without MFA requirement",
			[input.asset.role_name],
		),
		"Narrow trust Principal; add aws:MultiFactorAuthPresent or ExternalId conditions",
	)
}

iam_unified_msg(rule_id, severity, issue, remediation) := {
	"rule_id": rule_id,
	"issue": issue,
	"severity": severity,
	"framework": "CloudSecure Contextual Rules",
	"section": "IAM Unified Privilege",
	"status": "FAIL",
	"compliance": ["Contextual-Risk", "CIS 1.x", "CERT-In 2022"],
	"remediation": remediation,
}

# ---------------------------------------------------------------------------
# 4. RDS — unified data exposure
# ---------------------------------------------------------------------------

rds_sensitive_name if {
	sensitive_data_present
}

rds_sensitive_name if {
	name := lower(object.get(input.asset, "db_identifier", ""))
	regex.match(`.*(prod|finance|pii|customer|payment).*`, name)
}

deny contains msg if {
	input.asset.asset_type == "rds_instance"
	input.asset.publicly_accessible == true
	input.asset.db_port_exposed_from_internet == true
	input.asset.deletion_protection == false
	msg := rds_unified_msg(
		"CTX-RDS-PUBLIC-UNPROTECTED",
		"CRITICAL",
		sprintf(
			"RDS '%v' is publicly accessible with DB port reachable from internet and deletion protection disabled",
			[input.asset.db_identifier],
		),
		"Set publicly_accessible=false; restrict SG to private CIDRs; enable deletion protection",
	)
}

deny contains msg if {
	input.asset.asset_type == "rds_instance"
	input.asset.backup_retention == 0
	production_resource
	input.asset.multi_az == false
	msg := rds_unified_msg(
		"CTX-RDS-PROD-NO-BACKUP",
		"HIGH",
		sprintf(
			"RDS '%v' in production has automated backups disabled and is not Multi-AZ",
			[input.asset.db_identifier],
		),
		"Enable backup retention >= 7 days; enable Multi-AZ for production databases",
	)
}

deny contains msg if {
	input.asset.asset_type == "rds_instance"
	input.asset.storage_encrypted == false
	rds_sensitive_name
	msg := rds_unified_msg(
		"CTX-RDS-UNENCRYPTED-SENSITIVE",
		"CRITICAL",
		sprintf(
			"RDS '%v' has unencrypted storage and handles sensitive data (tag or naming pattern)",
			[input.asset.db_identifier],
		),
		"Migrate to encrypted RDS instance; use KMS CMK for sensitive databases",
	)
}

rds_unified_msg(rule_id, severity, issue, remediation) := {
	"rule_id": rule_id,
	"issue": issue,
	"severity": severity,
	"framework": "CloudSecure Contextual Rules",
	"section": "RDS Unified Exposure",
	"status": "FAIL",
	"compliance": ["Contextual-Risk", "CIS 4.3", "DPDP 2023", "RBI"],
	"remediation": remediation,
}

# ---------------------------------------------------------------------------
# 5. KMS — unified key misuse risk
# ---------------------------------------------------------------------------

deny contains msg if {
	input.asset.asset_type == "kms_key"
	input.asset.key_manager == "CUSTOMER"
	input.asset.key_state == "Enabled"
	input.asset.rotation_enabled == false
	object.get(input.asset, "key_age_days", 0) > 365
	msg := kms_unified_msg(
		"CTX-KMS-NO-ROTATION-OLD-ACTIVE",
		"HIGH",
		sprintf(
			"Customer-managed KMS key '%v' is enabled, older than 365 days, and automatic rotation is disabled",
			[input.asset.key_id],
		),
		"Enable key rotation: aws kms enable-key-rotation --key-id <key-id>",
	)
}

deny contains msg if {
	input.asset.asset_type == "kms_key"
	input.asset.key_manager == "CUSTOMER"
	input.asset.policy_allows_wildcard_decrypt == true
	input.asset.policy_has_service_condition == false
	object.get(input.asset, "is_default_service_key", false) == false
	msg := kms_unified_msg(
		"CTX-KMS-WILDCARD-DECRYPT",
		"CRITICAL",
		sprintf(
			"KMS key '%v' allows wildcard principal kms:Decrypt/GenerateDataKey without service/account condition",
			[input.asset.key_id],
		),
		"Restrict key policy Principal to account root or specific roles; add kms:ViaService condition",
	)
}

# Fallback when only flattened public-policy flag exists
deny contains msg if {
	input.asset.asset_type == "kms_key"
	input.asset.key_manager == "CUSTOMER"
	input.asset.key_policy_public_or_external == true
	not "policy_has_service_condition" in input.asset
	msg := kms_unified_msg(
		"CTX-KMS-PUBLIC-POLICY",
		"CRITICAL",
		sprintf(
			"KMS key '%v' key policy allows public or external account access without documented compensating condition",
			[input.asset.key_id],
		),
		"Replace Principal '*' with account-scoped principals and add Condition",
	)
}

kms_unified_msg(rule_id, severity, issue, remediation) := {
	"rule_id": rule_id,
	"issue": issue,
	"severity": severity,
	"framework": "CloudSecure Contextual Rules",
	"section": "KMS Unified Misuse",
	"status": "FAIL",
	"compliance": ["Contextual-Risk", "CIS 3.2", "RBI"],
	"remediation": remediation,
}

# ---------------------------------------------------------------------------
# 6. CloudTrail — unified logging gap
# ---------------------------------------------------------------------------

org_trail_backup_exists if {
	object.get(account_ctx, "organisation_trail_exists", false) == true
}

deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	input.asset.is_logging == false
	object.get(input.asset, "logging_gap_hours", 0) > 24
	not org_trail_backup_exists
	msg := cloudtrail_unified_msg(
		"CTX-CT-NOT-LOGGING-NO-ORG-BACKUP",
		"CRITICAL",
		sprintf(
			"CloudTrail '%v' is not logging (gap >24h) and no organisation-level trail provides backup coverage",
			[input.asset.name],
		),
		"Start logging on the trail; configure organisation CloudTrail as backup",
	)
}

deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	input.asset.is_multi_region == false
	object.get(account_ctx, "multi_region_resources", false) == true
	msg := cloudtrail_unified_msg(
		"CTX-CT-SINGLE-REGION-MULTI-RESOURCE",
		"HIGH",
		sprintf(
			"CloudTrail '%v' is single-region but account has multi-region resources — audit blind spots in other regions",
			[input.asset.name],
		),
		"Enable multi-region trail or add trails per region",
	)
}

deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	input.asset.s3_bucket_public == true
	input.asset.log_file_validation_enabled == false
	object.get(input.asset, "is_only_trail_in_account", false) == true
	msg := cloudtrail_unified_msg(
		"CTX-CT-LOG-BUCKET-WEAK",
		"CRITICAL",
		sprintf(
			"CloudTrail '%v' is the only account trail, log bucket is public or validation disabled — tamper/evidence risk",
			[input.asset.name],
		),
		"Secure log S3 bucket (BPA); enable log file validation; add secondary trail",
	)
}

# Partial fallback: public log bucket + no validation (both weak signals together)
deny contains msg if {
	input.asset.asset_type == "cloudtrail_trail"
	input.asset.s3_bucket_public == true
	input.asset.log_file_validation_enabled == false
	not "is_only_trail_in_account" in input.asset
	msg := cloudtrail_unified_msg(
		"CTX-CT-LOG-INTEGRITY-RISK",
		"HIGH",
		sprintf(
			"CloudTrail '%v' log bucket is publicly accessible and log file validation is disabled",
			[input.asset.name],
		),
		"Block public access on log bucket; enable log file validation",
	)
}

cloudtrail_unified_msg(rule_id, severity, issue, remediation) := {
	"rule_id": rule_id,
	"issue": issue,
	"severity": severity,
	"framework": "CloudSecure Contextual Rules",
	"section": "CloudTrail Unified Logging",
	"status": "FAIL",
	"compliance": ["Contextual-Risk", "CIS 3.1", "CERT-In 2022"],
	"remediation": remediation,
}

# ---------------------------------------------------------------------------
# 7. Security groups — unified dangerous exposure
# ---------------------------------------------------------------------------

deny contains msg if {
	input.asset.asset_type == "security_group"
	input.asset.allows_ssh == true
	input.asset.attached_to_running_instance == true
	input.asset.attached_instance_has_public_ip == true
	msg := sg_unified_msg(
		"CTX-SG-SSH-PUBLIC-INSTANCE",
		"CRITICAL",
		sprintf(
			"Security group '%v' allows SSH from internet and is attached to a running instance with public IP",
			[input.asset.group_id],
		),
		"Revoke 0.0.0.0/0:22; remove public IP from instance; use SSM Session Manager",
	)
}

deny contains msg if {
	input.asset.asset_type == "security_group"
	input.asset.allows_rdp == true
	input.asset.attached_to_running_instance == true
	input.asset.attached_instance_has_public_ip == true
	msg := sg_unified_msg(
		"CTX-SG-RDP-PUBLIC-INSTANCE",
		"CRITICAL",
		sprintf(
			"Security group '%v' allows RDP from internet and is attached to a running instance with public IP",
			[input.asset.group_id],
		),
		"Revoke 0.0.0.0/0:3389; remove public IP; use VPN or bastion with restricted access",
	)
}

deny contains msg if {
	input.asset.asset_type == "security_group"
	input.asset.allows_all_ingress == true
	not intentionally_open_exposure
	msg := sg_unified_msg(
		"CTX-SG-ALL-PORTS-UNMARKED",
		"CRITICAL",
		sprintf(
			"Security group '%v' allows all inbound ports from internet and is not tagged exposure=intentional",
			[input.asset.group_id],
		),
		"Remove 0.0.0.0/0 all-port rules or tag with documented business justification and compensating controls",
	)
}

deny contains msg if {
	input.asset.asset_type == "security_group"
	input.asset.allows_all_egress == true
	input.asset.attached_instance_iam_data_access == true
	msg := sg_unified_msg(
		"CTX-SG-EGRESS-DATA-EXFIL",
		"HIGH",
		sprintf(
			"Security group '%v' allows all outbound traffic and is attached to an instance whose IAM role grants data-store access (S3/RDS/Secrets Manager)",
			[input.asset.group_id],
		),
		"Restrict egress to required destinations; scope IAM role to least privilege; add VPC endpoints",
	)
}

sg_unified_msg(rule_id, severity, issue, remediation) := {
	"rule_id": rule_id,
	"issue": issue,
	"severity": severity,
	"framework": "CloudSecure Contextual Rules",
	"section": "Security Group Unified Exposure",
	"status": "FAIL",
	"compliance": ["Contextual-Risk", "CIS 4.1", "CERT-In 2022"],
	"remediation": remediation,
}
