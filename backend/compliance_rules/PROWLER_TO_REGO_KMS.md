# KMS — Prowler checks and Rego mapping

## Service: `providers/aws/services/kms/`

---

## Table 1 — Every Prowler check: CheckID | Severity | FAIL condition (plain English) | Remediation CLI

| CheckID | Severity | FAIL Condition (plain English) | Remediation CLI |
|---------|----------|--------------------------------|-----------------|
| kms_key_not_publicly_accessible | critical | KMS key policy allows access to a principal other than the account root (e.g. "*" or external account). | aws kms put-key-policy --key-id &lt;id&gt; --policy-name default --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::&lt;account_id&gt;:root"},"Action":"kms:*","Resource":"*"}]}' |
| kms_cmk_rotation_enabled | high | Customer managed key (CMK) does not have automatic key rotation enabled. | aws kms enable-key-rotation --key-id &lt;KEY_ID&gt; |
| kms_cmk_not_deleted_unintentionally | critical | KMS CMK is in PendingDeletion state (scheduled for deletion). | aws kms cancel-key-deletion --key-id &lt;KEY_ID&gt; |
| kms_cmk_not_multi_region | medium | CMK is a multi-region key (replication risk / operational preference). | (Create single-region key and migrate; no enable single-region CLI) |
| kms_cmk_are_used | low | CMK has not been used recently (stale/orphaned key). | aws kms enable-key --key-id &lt;key_id&gt; (if disabled) or document exception |

---

## Table 2 — Rego rule per check + what we add over Prowler

| Prowler CheckID | Our Rego rule (replacement) | What we add that Prowler does not have |
|-----------------|----------------------------|----------------------------------------|
| kms_key_not_publicly_accessible | cis_aws_kms + india_aws_kms: deny when key policy has principal "*" or external account | CIS + DPDP/CERT-In/RBI; exact put-key-policy CLI; rationale. |
| kms_cmk_rotation_enabled | cis_aws_kms + india_aws_kms: deny when rotation_enabled false for customer CMK | CIS + RBI; enable-key-rotation CLI. |
| kms_cmk_not_deleted_unintentionally | cis_aws_kms + india_aws_kms: deny when key state is PendingDeletion | CIS + India; cancel-key-deletion CLI. |
| kms_cmk_not_multi_region | cis_aws_kms: deny when key is multi-region (if we want to enforce single-region) | CIS; remediation “use single-region CMK”. |
| kms_cmk_are_used | Optional (low): deny when key not used in X days | Rationale; document or disable. |

---

*Next: CloudTrail.*
