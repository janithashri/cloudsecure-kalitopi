# S3 — Prowler checks and Rego mapping

## Service: `providers/aws/services/s3/`

---

## Table 1 — Every Prowler check: CheckID | Severity | FAIL condition (plain English) | Remediation CLI

| CheckID | Severity | FAIL Condition (plain English) | Remediation CLI |
|---------|----------|--------------------------------|-----------------|
| s3_bucket_public_access | critical | Bucket has public access: either ACL grants to AllUsers/AuthenticatedUsers or bucket policy allows public access; and Block Public Access (IgnorePublicAcls, RestrictPublicBuckets) not effective at account or bucket level. | aws s3api put-public-access-block --bucket &lt;bucket_name&gt; --public-access-block-configuration IgnorePublicAcls=true,RestrictPublicBuckets=true |
| s3_bucket_level_public_access_block | high | Bucket (or account) does not have Block Public Access with IgnorePublicAcls and RestrictPublicBuckets both true. | aws s3api put-public-access-block --bucket &lt;BUCKET_NAME&gt; --public-access-block-configuration IgnorePublicAcls=true,RestrictPublicBuckets=true |
| s3_bucket_secure_transport_policy | medium | Bucket has no policy that denies requests when aws:SecureTransport is false (allows HTTP). | aws s3api put-bucket-policy --bucket &lt;bucket&gt; --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::&lt;bucket&gt;/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}' |
| s3_bucket_no_mfa_delete | medium | Bucket has versioning enabled but MFA Delete is not enabled. | aws s3api put-bucket-versioning --bucket &lt;BUCKET_NAME&gt; --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa "&lt;MFA_SERIAL_OR_ARN&gt; &lt;MFA_CODE&gt;" |
| s3_bucket_server_access_logging_enabled | medium | Bucket does not have server access logging configured (no LoggingEnabled target). | aws s3api put-bucket-logging --bucket &lt;BUCKET_NAME&gt; --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"&lt;LOG_BUCKET&gt;","TargetPrefix":"logs/"}}' |
| s3_bucket_default_encryption | medium | Bucket has no default server-side encryption (SSE) configuration. | aws s3api put-bucket-encryption --bucket &lt;bucket_name&gt; --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' |
| s3_bucket_public_write_acl | critical | Bucket ACL grants WRITE, WRITE_ACP, or FULL_CONTROL to AllUsers or AuthenticatedUsers, and Block Public Access does not effectively block it. | aws s3api put-bucket-acl --bucket &lt;bucket_name&gt; --acl private |
| s3_bucket_public_list_acl | critical | Bucket ACL grants READ, READ_ACP, or FULL_CONTROL to AllUsers or AuthenticatedUsers, and Block Public Access does not effectively block it. | aws s3api put-public-access-block --bucket &lt;bucket_name&gt; --public-access-block-configuration IgnorePublicAcls=true,RestrictPublicBuckets=true |
| s3_bucket_policy_public_write_access | critical | Bucket policy allows public write (e.g. s3:PutObject, s3:Delete* to Principal "*") and RestrictPublicBuckets is not preventing it. | aws s3api put-public-access-block --bucket &lt;BUCKET_NAME&gt; --public-access-block-configuration RestrictPublicBuckets=true |
| s3_bucket_object_versioning | medium | Bucket does not have object versioning enabled (Status != Enabled). | aws s3api put-bucket-versioning --bucket &lt;BUCKET_NAME&gt; --versioning-configuration Status=Enabled |
| s3_bucket_kms_encryption | medium | Bucket default encryption is not SSE-KMS (aws:kms or aws:kms:dsse). | aws s3api put-bucket-encryption --bucket &lt;BUCKET_NAME&gt; --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}' |
| s3_account_level_public_access_blocks | high | Account-level S3 Block Public Access does not have IgnorePublicAcls and RestrictPublicBuckets true. | aws s3control put-public-access-block --account-id &lt;account_id&gt; --public-access-block-configuration IgnorePublicAcls=true,RestrictPublicBuckets=true |
| s3_bucket_cross_account_access | high | Bucket policy grants access to principals outside the owning account (other account IDs or Principal "*"). | aws s3api delete-bucket-policy --bucket &lt;bucket&gt; (or edit policy to restrict to own account) |
| s3_bucket_acl_prohibited | medium | Object Ownership is not BucketOwnerEnforced (ACLs are still usable). | aws s3api put-bucket-ownership-controls --bucket &lt;bucket-name&gt; --ownership-controls "Rules=[{ObjectOwnership=BucketOwnerEnforced}]" |
| s3_bucket_object_lock | low | Bucket does not have Object Lock enabled. | aws s3api put-object-lock-configuration --bucket &lt;BUCKET_NAME&gt; --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{...}}' |
| s3_bucket_lifecycle_enabled | low | Bucket has no lifecycle configuration with at least one rule Status=Enabled. | aws s3api put-bucket-lifecycle-configuration --bucket &lt;BUCKET_NAME&gt; --lifecycle-configuration '{"Rules":[{"Status":"Enabled","Filter":{"Prefix":""},"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":7}}]}' |
| s3_bucket_event_notifications_enabled | low | Bucket has no event notification configuration (e.g. EventBridge, SNS, SQS, Lambda). | aws s3api put-bucket-notification-configuration --bucket &lt;BUCKET_NAME&gt; --notification-configuration '{"EventBridgeConfiguration":{}}' |
| s3_bucket_cross_region_replication | low | Bucket does not have cross-region replication with versioning and an enabled rule to a different region. | (No single CLI; enable versioning + create replication rule via console/CloudFormation/Terraform) |
| s3_access_point_public_access_block | critical | S3 Access Point does not have all four Block Public Access settings enabled. | (CLI empty in Prowler; use console or IaC to create/update access point with BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets true) |
| s3_multi_region_access_point_public_access_block | high | Multi-Region Access Point does not have all Block Public Access settings enabled. | (Settings immutable after creation; create new MRAP with all four block settings enabled) |
| s3_bucket_shadow_resource_vulnerability | high | Bucket name matches predictable service pattern (e.g. aws-glue-assets-&lt;account&gt;-&lt;region&gt;) but bucket is owned by another account. | Pre-claim bucket: aws s3api create-bucket --bucket &lt;FLAGGED_BUCKET_NAME&gt; --region &lt;region&gt; |

---

## Table 2 — Rego rule per check + what we add over Prowler

| Prowler CheckID | Our Rego rule (replacement) | What we add that Prowler does not have |
|-----------------|----------------------------|----------------------------------------|
| s3_bucket_public_access | cis_aws_s3 + india_aws_s3: deny when is_public (any block_public_* false/missing or public ACL/policy) | DPDP 2023 + CERT-In mapping; contextual severity (e.g. production tag → CRITICAL); step-by-step remediation + exact CLI; rationale comment. |
| s3_bucket_level_public_access_block | cis_aws_s3: deny when block_public_acls/ignore_public_acls/block_public_policy/restrict_public_buckets not all true at bucket (or account) | Multi-framework compliance in deny msg; India (DPDP/CERT-In); exact CLI with bucket placeholder. |
| s3_bucket_secure_transport_policy | cis_aws_s3: deny when bucket policy does not deny aws:SecureTransport=false | CIS + India mapping; remediation with full policy JSON and CLI. |
| s3_bucket_no_mfa_delete | cis_aws_s3: deny when versioning enabled and mfa_delete not enabled | CIS 2.1.2 + India; remediation steps + MFA CLI. |
| s3_bucket_server_access_logging_enabled | cis_aws_s3 + india_aws_s3: deny when access_logging_enabled false | CIS + CERT-In; compound note: public + no logging = higher severity; exact put-bucket-logging CLI. |
| s3_bucket_default_encryption | cis_aws_s3 + india_aws_s3: deny when server_side_encryption_enabled false | CIS + DPDP/RBI (data protection); contextual severity for buckets with PII tags; CLI for AES256 and KMS. |
| s3_bucket_public_write_acl | cis_aws_s3 + india_aws_s3: deny when public write via ACL (and not blocked) | Same as public_access; compound with public list for single “public exposure” message where applicable. |
| s3_bucket_public_list_acl | cis_aws_s3 + india_aws_s3: deny when public list via ACL (and not blocked) | As above; can combine with public_write in one rule for “public ACL” where desired. |
| s3_bucket_policy_public_write_access | cis_aws_s3 + india_aws_s3: deny when has_cross_account_policy or policy allows public write | CIS + India; remediation RestrictPublicBuckets + policy review CLI. |
| s3_bucket_object_versioning | cis_aws_s3: deny when versioning not enabled | CIS + resilience; rationale + CLI. |
| s3_bucket_kms_encryption | cis_aws_s3 + india_aws_s3: deny when encryption_type != aws:kms (optional / configurable for high-sensitivity only) | CIS + DPDP/RBI; “prefer KMS” rationale; CLI for SSE-KMS. |
| s3_account_level_public_access_blocks | cis_aws_s3 (account-level input or separate policy): deny when account block public access not set | CIS 2.1.4; India; CLI with account-id. |
| s3_bucket_cross_account_access | india_aws_s3 + cis_aws_s3: deny when has_cross_account_policy (policy principals include other account or "*") | CERT-In/DPDP trust boundaries; optional trusted_account_ids in input; remediation CLI. |
| s3_bucket_acl_prohibited | cis_aws_s3: deny when object_ownership != BucketOwnerEnforced (if field available) | CIS + India; rationale “disable ACLs”; put-bucket-ownership-controls CLI. |
| s3_bucket_object_lock | Optional Rego (low): deny when object_lock_enabled false | Rationale + remediation; low severity. |
| s3_bucket_lifecycle_enabled | Optional Rego (low): deny when no lifecycle rule enabled | Rationale; put-bucket-lifecycle-configuration CLI. |
| s3_bucket_event_notifications_enabled | Optional Rego (low): deny when no event notifications | NIST mapping; EventBridge CLI. |
| s3_bucket_cross_region_replication | Optional Rego (low): deny when no CRR to different region | Resilience; no single CLI in table. |
| s3_access_point_public_access_block | Omit in v1 (access points not in fetcher) or add when we have access-point asset type | When added: same improvements as bucket-level block; India mapping. |
| s3_multi_region_access_point_public_access_block | Omit in v1 (MRAP not in fetcher) | When added: same as above. |
| s3_bucket_shadow_resource_vulnerability | Optional: Rego + input with predictable-name pattern + owner account; or leave to post-process | When supported: rationale + pre-claim CLI. |

---

*Next: IAM, then EC2, RDS, KMS, CloudTrail.*
