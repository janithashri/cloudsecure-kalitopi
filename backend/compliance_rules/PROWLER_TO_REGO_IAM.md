# IAM — Prowler checks and Rego mapping

## Service: `providers/aws/services/iam/`

---

## Table 1 — Every Prowler check: CheckID | Severity | FAIL condition (plain English) | Remediation CLI

| CheckID | Severity | FAIL Condition (plain English) | Remediation CLI |
|---------|----------|--------------------------------|-----------------|
| iam_user_mfa_enabled_console_access | high | IAM user has console password enabled but MFA is not active. | aws iam delete-login-profile --user-name &lt;IAM_USER_NAME&gt; (or enable MFA in console) |
| iam_user_hardware_mfa_enabled | high | IAM user with console access does not have hardware MFA (U2F/Hardware token). | (Console: assign hardware MFA device) |
| iam_user_administrator_access_policy | critical | IAM user has AdministratorAccess policy attached (directly or via group). | aws iam detach-user-policy --user-name &lt;username&gt; --policy-arn arn:aws:iam::aws:policy/AdministratorAccess |
| iam_user_accesskey_unused | medium | IAM user has an active access key unused for 45+ days (or never used). | aws iam update-access-key --user-name &lt;USER_NAME&gt; --access-key-id &lt;ACCESS_KEY_ID&gt; --status Inactive |
| iam_user_console_access_unused | medium | IAM user has console password and has not signed in for 45+ days. | aws iam delete-login-profile --user-name &lt;USER_NAME&gt; |
| iam_user_two_active_access_key | medium | IAM user has more than one active access key. | aws iam update-access-key --user-name &lt;IAM_USER_NAME&gt; --access-key-id &lt;ACCESS_KEY_ID&gt; --status Inactive |
| iam_user_no_setup_initial_access_key | medium | IAM user had access key created at same time as user and it is unused. | aws iam delete-access-key --user-name &lt;user&gt; --access-key-id &lt;key-id&gt; |
| iam_user_with_temporary_credentials | high | IAM user can use long-term credentials for actions that should require temporary (STS) credentials. | aws iam put-user-policy ... (deny without aws:TokenIssueTime) |
| iam_rotate_access_key_90_days | medium | IAM user has active access key older than 90 days (not rotated). | aws iam update-access-key --user-name &lt;USER_NAME&gt; --access-key-id &lt;ACCESS_KEY_ID&gt; --status Inactive |
| iam_root_mfa_enabled | critical | Root account does not have MFA enabled. | (Console only: assign MFA to root) |
| iam_root_hardware_mfa_enabled | critical | Root account does not have hardware MFA enabled. | (Console only) |
| iam_no_root_access_key | critical | Root account has an active access key. | (Console: delete root access keys) |
| iam_root_credentials_management_enabled | high | Root account does not have Organizations root credentials management enabled. | aws iam enable-organizations-root-credentials-management |
| iam_avoid_root_usage | high | Root account was used in last 24h (activity). | (Operational: stop using root) |
| iam_policy_attached_only_to_group_or_roles | low | IAM user has inline policy or directly attached managed policy (should only get permissions via groups). | (Console: move permissions to group, detach from user) |
| iam_policy_allows_privilege_escalation | high | Managed policy allows privilege escalation (e.g. iam:PutUserPolicy, iam:AttachRolePolicy to broader role). | aws iam create-policy-version --policy-arn &lt;id&gt; --set-as-default --policy-document ... |
| iam_role_administratoraccess_policy | high | IAM role has AdministratorAccess policy attached. | aws iam detach-role-policy --role-name &lt;ROLE_NAME&gt; --policy-arn arn:aws:iam::aws:policy/AdministratorAccess |
| iam_role_cross_account_readonlyaccess_policy | high | IAM role has ReadOnlyAccess and is assumable by another account (overly permissive cross-account). | aws iam detach-role-policy --role-name &lt;ROLE_NAME&gt; --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess |
| iam_role_cross_service_confused_deputy_prevention | high | Role trust policy does not restrict by aws:SourceAccount / aws:SourceArn (confused deputy risk). | aws iam update-assume-role-policy --role-name &lt;role&gt; --policy-document '{"Condition":{"StringEquals":{"aws:SourceAccount":"&lt;ACCOUNT_ID&gt;"}}}' |
| iam_policy_no_full_access_to_kms | medium | Managed policy grants kms:* or full KMS access instead of least privilege. | aws iam create-policy-version --policy-arn &lt;arn&gt; ... (scope to specific key/actions) |
| iam_policy_no_full_access_to_cloudtrail | medium | Managed policy grants cloudtrail:* or full CloudTrail access instead of least privilege. | aws iam create-policy-version --policy-arn &lt;arn&gt; ... (scope to DescribeTrails etc.) |
| iam_policy_cloudshell_admin_not_attached | medium | AWS managed policy AdministratorAccess-AWSElasticBeanstalk or similar is attached (CloudShell admin). | (Detach policy) |
| iam_password_policy_uppercase | medium | Account password policy does not require uppercase characters. | aws iam update-account-password-policy --require-uppercase-characters |
| iam_password_policy_lowercase | low | Account password policy does not require lowercase characters. | aws iam update-account-password-policy --require-lowercase-characters |
| iam_password_policy_number | medium | Account password policy does not require numbers. | aws iam update-account-password-policy --require-numbers |
| iam_password_policy_symbol | medium | Account password policy does not require symbols. | aws iam update-account-password-policy --require-symbols |
| iam_password_policy_minimum_length_14 | medium | Account password policy minimum length is less than 14. | aws iam update-account-password-policy --minimum-password-length 14 |
| iam_password_policy_reuse_24 | medium | Account password policy does not prevent reuse of last 24 passwords. | aws iam update-account-password-policy --password-reuse-prevention 24 |
| iam_password_policy_expires_passwords_within_90_days_or_less | medium | Account password policy does not expire passwords within 90 days. | aws iam update-account-password-policy --max-password-age 90 |
| iam_no_expired_server_certificates_stored | high | IAM has expired server certificate stored. | aws iam delete-server-certificate --server-certificate-name &lt;CERTIFICATE_NAME&gt; |
| iam_no_custom_policy_permissive_role_assumption | high | Custom policy allows sts:AssumeRole to "*" or broad resource (overly permissive). | aws iam create-policy-version --policy-arn &lt;arn&gt; ... (restrict Resource to specific role ARNs) |
| iam_inline_policy_no_full_access_to_kms | medium | Inline policy on user/role/group grants full KMS access. | (Edit inline policy to least privilege) |
| iam_inline_policy_no_full_access_to_cloudtrail | high | Inline policy grants full CloudTrail access. | (Edit inline policy) |
| iam_inline_policy_no_administrative_privileges | critical | Inline policy grants administrative privileges (e.g. "*" on "*"). | (Remove or narrow inline policy) |
| iam_inline_policy_allows_privilege_escalation | high | Inline policy allows privilege escalation. | (Edit/remove inline policy) |
| iam_group_administrator_access_policy | high | IAM group has AdministratorAccess attached. | aws iam detach-group-policy --group-name &lt;groupname&gt; --policy-arn arn:aws:iam::aws:policy/AdministratorAccess |
| iam_administrator_access_with_mfa | high | User/group has AdministratorAccess without MFA requirement for sensitive actions. | aws iam detach-group-policy ... (and enforce MFA via policy condition) |
| iam_customer_attached_policy_no_administrative_privileges | high | Customer managed policy attached to identity grants admin-level privileges. | aws iam create-policy-version ... (narrow policy) |
| iam_customer_unattached_policy_no_administrative_privileges | medium | Unattached customer managed policy has admin-level privileges (drift risk). | aws iam create-policy-version ... |
| iam_aws_attached_policy_no_administrative_privileges | critical | AWS managed policy that grants admin is attached (e.g. AdministratorAccess). | (Detach or replace with custom least-privilege) |
| iam_support_role_created | low | AWSSupportAccess role does not exist. | aws iam attach-role-policy --role-name &lt;role&gt; --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess |
| iam_securityaudit_role_created | low | SecurityAudit role does not exist. | aws iam attach-role-policy --role-name &lt;role&gt; --policy-arn arn:aws:iam::aws:policy/SecurityAudit |
| iam_check_saml_providers_sts | low | No SAML provider configured for federation (optional). | aws iam create-saml-provider --name &lt;name&gt; --saml-metadata-document file://&lt;file&gt; |

---

## Table 2 — Rego rule per check + what we add over Prowler

| Prowler CheckID | Our Rego rule (replacement) | What we add that Prowler does not have |
|-----------------|----------------------------|----------------------------------------|
| iam_user_mfa_enabled_console_access | cis_aws_iam + india_aws_iam: deny when iam_user has console password and mfa_enabled false | CERT-In 2022 + DPDP mapping; contextual severity for admin users; step-by-step + MFA CLI; rationale. |
| iam_user_hardware_mfa_enabled | Optional: deny when console user and not hardware MFA (if fetcher provides MFA type) | CERT-In; remediation “prefer hardware MFA”. |
| iam_user_administrator_access_policy | cis_aws_iam + india_aws_iam: deny when user has AdministratorAccess (or equivalent) | CIS 1.16 + India; severity CRITICAL; detach-user-policy CLI. |
| iam_user_accesskey_unused | cis_aws_iam: deny when access_key_active and last_used &gt; 45 days ago (or N/A and created with user) | CIS 1.12 + CERT-In; deactivate CLI. |
| iam_user_console_access_unused | cis_aws_iam: deny when password_enabled and password_last_used &gt; 45 days | CIS 1.12; delete-login-profile CLI. |
| iam_user_two_active_access_key | cis_aws_iam: deny when more than one active access key | CIS 1.13; update-access-key Inactive CLI. |
| iam_user_no_setup_initial_access_key | cis_aws_iam: deny when key created at user creation and never used | CIS 1.11; delete-access-key CLI. |
| iam_user_with_temporary_credentials | india_aws_iam: deny when user policy allows broad actions without aws:TokenIssueTime condition | CERT-In; remediation with policy snippet. |
| iam_rotate_access_key_90_days | cis_aws_iam: deny when access_key_last_rotated &gt; 90 days | CIS 1.14; rotate + deactivate CLI. |
| iam_root_mfa_enabled | cis_aws_iam (account-level): root has no MFA | CIS 1.2 + CERT-In; console-only remediation. |
| iam_root_hardware_mfa_enabled | Optional: root without hardware MFA | Same + “prefer hardware for root”. |
| iam_no_root_access_key | cis_aws_iam (account-level): root has access key | CIS 1.3 critical; remediation. |
| iam_root_credentials_management_enabled | cis_aws_iam: root credentials management not enabled | CIS; enable-organizations-root-credentials-management CLI. |
| iam_avoid_root_usage | Optional (activity data): root used recently | Operational guidance. |
| iam_policy_attached_only_to_group_or_roles | cis_aws_iam: deny when user has inline or directly attached policy | CIS 1.15; rationale + console steps. |
| iam_policy_allows_privilege_escalation | cis_aws_iam + india_aws_iam: deny when policy allows escalation (e.g. iam:PutUserPolicy on *) | CIS + CERT-In; create-policy-version deny. |
| iam_role_administratoraccess_policy | cis_aws_iam + india_aws_iam: deny when role has AdministratorAccess | detach-role-policy CLI; India mapping. |
| iam_role_cross_account_readonlyaccess_policy | india_aws_iam: deny when role has ReadOnlyAccess and trust allows cross-account | CERT-In trust boundaries; detach or narrow trust. |
| iam_role_cross_service_confused_deputy_prevention | cis_aws_iam + india_aws_iam: deny when assume_role_policy has no aws:SourceAccount/SourceArn | CIS + India; update-assume-role-policy CLI. |
| iam_policy_no_full_access_to_kms | cis_aws_iam: deny when policy has kms:* on * | Scoped KMS actions; create-policy-version example. |
| iam_policy_no_full_access_to_cloudtrail | cis_aws_iam: deny when policy has cloudtrail:* on * | Scoped CloudTrail; same. |
| iam_policy_cloudshell_admin_not_attached | Optional: flag CloudShell admin policy | Medium; detach. |
| iam_password_policy_* (all 8) | cis_aws_iam (account-level): deny when password policy missing require_uppercase/lowercase/numbers/symbols/min_length/reuse/max_age | CIS 1.5–1.8 + CERT-In; update-account-password-policy CLI per finding. |
| iam_no_expired_server_certificates_stored | cis_aws_iam: deny when expired server cert in IAM | delete-server-certificate CLI. |
| iam_no_custom_policy_permissive_role_assumption | india_aws_iam: deny when custom policy has sts:AssumeRole Resource "*" | CERT-In; narrow Resource. |
| iam_inline_policy_* (KMS, CloudTrail, admin, privilege escalation) | cis_aws_iam + india_aws_iam: deny when inline policy on user/role/group is over-privileged | Same improvements; remediation “edit inline policy” + example. |
| iam_group_administrator_access_policy | cis_aws_iam: deny when group has AdministratorAccess | detach-group-policy CLI. |
| iam_administrator_access_with_mfa | cis_aws_iam: deny when AdministratorAccess without MFA condition | Require MFA in policy condition; detach or add condition. |
| iam_customer_attached/unattached_policy_no_administrative_privileges | cis_aws_iam: deny when customer policy grants *:* or admin actions on * | create-policy-version with least privilege. |
| iam_aws_attached_policy_no_administrative_privileges | cis_aws_iam: deny when AWS managed admin policy attached | Critical; detach. |
| iam_support_role_created | cis_aws_iam (optional): support role missing | attach-role-policy AWSSupportAccess. |
| iam_securityaudit_role_created | cis_aws_iam (optional): SecurityAudit role missing | attach-role-policy SecurityAudit. |
| iam_check_saml_providers_sts | Optional / omit in v1 | Low; federation. |

---

*Next: EC2, RDS, KMS, CloudTrail.*
