# EC2 — Prowler checks and Rego mapping

## Service: `providers/aws/services/ec2/`

---

## Table 1 — Every Prowler check: CheckID | Severity | FAIL condition (plain English) | Remediation CLI

| CheckID | Severity | FAIL Condition (plain English) | Remediation CLI |
|---------|----------|--------------------------------|-----------------|
| ec2_securitygroup_allow_ingress_from_internet_to_all_ports | critical | Security group has an ingress rule allowing all ports (protocol -1 or 0-65535) from 0.0.0.0/0 or ::/0. | (Edit SG: remove rule; no single CLI in Prowler) |
| ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 | high | Security group allows TCP port 22 (SSH) from 0.0.0.0/0 or ::/0. | aws ec2 revoke-security-group-ingress --group-id &lt;SG_ID&gt; --protocol tcp --port 22 --cidr 0.0.0.0/0 |
| ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389 | high | Security group allows TCP port 3389 (RDP) from 0.0.0.0/0 or ::/0. | aws ec2 revoke-security-group-ingress --group-id &lt;SG_ID&gt; --protocol tcp --port 3389 --cidr 0.0.0.0/0 |
| ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports | high | Security group allows high-risk TCP ports (e.g. 21,22,23,25,110,143,445,3389,5432,5900, etc.) from internet. | (Revoke per port) |
| ec2_securitygroup_allow_ingress_from_internet_to_any_port | high | Security group allows a specific port from 0.0.0.0/0 (any port exposed to internet). | (Revoke rule) |
| ec2_securitygroup_allow_wide_open_public_ipv4 | high | Security group allows all IPv4 traffic (0.0.0.0/0) on all ports. | (Revoke ingress) |
| ec2_securitygroup_default_restrict_traffic | high | Default security group has any allow rule (should restrict all traffic). | (Remove rules from default SG) |
| ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_* (22, 23, 3306, 5432, 6379, 11211, 1433/1434, 27017/27018, 9092, 20/21, 7199/9160/8888) | high | SG allows respective DB/management port from 0.0.0.0/0. | aws ec2 revoke-security-group-ingress --group-id &lt;SG_ID&gt; --protocol tcp --port &lt;port&gt; --cidr 0.0.0.0/0 (or ip-permissions JSON) |
| ec2_securitygroup_not_used | low | Security group is not attached to any ENI. | aws ec2 delete-security-group --group-id &lt;SECURITY_GROUP_ID&gt; |
| ec2_securitygroup_from_launch_wizard | medium | Security group was created by EC2 Launch Wizard (often over-permissive). | aws ec2 delete-security-group --group-id &lt;SG_ID&gt; |
| ec2_securitygroup_with_many_ingress_egress_rules | medium | Security group has many rules (e.g. &gt;50); operational risk. | (Consolidate rules) |
| ec2_networkacl_allow_ingress_any_port | high | NACL has an ingress rule allowing all traffic from 0.0.0.0/0. | aws ec2 replace-network-acl-entry ... --rule-action deny |
| ec2_networkacl_allow_ingress_tcp_port_22 | medium | NACL allows TCP 22 from 0.0.0.0/0. | aws ec2 replace-network-acl-entry ... --port-range From=22,To=22 ... |
| ec2_networkacl_allow_ingress_tcp_port_3389 | medium | NACL allows TCP 3389 from 0.0.0.0/0. | aws ec2 delete-network-acl-entry ... |
| ec2_networkacl_unused | low | NACL is not associated with any subnet. | aws ec2 delete-network-acl --network-acl-id &lt;nacl_id&gt; |
| ec2_instance_public_ip | medium | EC2 instance has a public IP address. | (Release or use private only) |
| ec2_instance_profile_attached | medium | EC2 instance has no IAM instance profile attached. | aws ec2 associate-iam-instance-profile --instance-id &lt;ID&gt; --iam-instance-profile Name=&lt;PROFILE&gt; |
| ec2_instance_port_ssh_exposed_to_internet | critical | Instance has SSH (22) exposed to internet (public IP + SG allows 22 from 0.0.0.0/0). | aws ec2 revoke-security-group-ingress ... |
| ec2_instance_port_telnet_exposed_to_internet | critical | Instance has Telnet (23) exposed to internet. | aws ec2 revoke-security-group-ingress ... --port 23 |
| ec2_instance_port_sqlserver_exposed_to_internet | critical | Instance has SQL Server ports exposed to internet. | aws ec2 revoke-security-group-ingress ... |
| ec2_instance_secrets_user_data | high | Instance user data contains secrets (e.g. password in plaintext). | aws ec2 modify-instance-attribute --instance-id &lt;ID&gt; --user-data "" |
| ec2_launch_template_no_public_ip | high | Launch template sets AssociatePublicIpAddress true (or default). | aws ec2 create-launch-template-version ... --launch-template-data '{"NetworkInterfaces":[{"AssociatePublicIpAddress":false}]}' |
| ec2_launch_template_imdsv2_required | high | Launch template does not require IMDSv2 (HttpTokens required). | aws ec2 create-launch-template-version ... --launch-template-data '{"MetadataOptions":{"HttpTokens":"required"}}' |
| ec2_launch_template_no_secrets | high | Launch template user data contains secrets. | (Remove secrets; use SSM/Secrets Manager) |
| ec2_instance_with_outdated_ami | medium | Instance uses an AMI that is deprecated or outdated. | (Replace with current AMI) |
| ec2_instance_uses_single_eni | low | Instance has single ENI (availability concern). | (Operational) |
| ec2_transitgateway_auto_accept_vpc_attachments | high | Transit Gateway has AutoAcceptSharedAttachments enabled. | aws ec2 modify-transit-gateway ... --options AutoAcceptSharedAttachments=disable |

*(Additional EC2 checks in Prowler: other SG port-specific checks, NACL checks, EBS encryption, etc.—same pattern: deny when condition + revoke/modify CLI.)*

---

## Table 2 — Rego rule per check + what we add over Prowler

| Prowler CheckID | Our Rego rule (replacement) | What we add that Prowler does not have |
|-----------------|----------------------------|----------------------------------------|
| ec2_securitygroup_allow_ingress_from_internet_to_all_ports | cis_aws_ec2 + india_aws_ec2: deny when allows_all_ingress (any rule: protocol -1 and cidr 0.0.0.0/0) | CIS + CERT-In/DPDP; contextual severity (e.g. production VPC); exact revoke CLI; rationale. |
| ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 | cis_aws_ec2 + india_aws_ec2: deny when allows_ssh (port 22 from 0.0.0.0/0) | Same; revoke-security-group-ingress with port 22. |
| ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389 | cis_aws_ec2 + india_aws_ec2: deny when allows_rdp (port 3389 from 0.0.0.0/0) | Same; port 3389. |
| ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports | cis_aws_ec2: deny when any high-risk port (21,22,23,3306,5432, etc.) from 0.0.0.0/0 | Single rule with port list; CERT-In; remediation per port. |
| ec2_securitygroup_allow_wide_open_public_ipv4 | Same as allows_all_ports / allows_all_ingress | Critical severity; compound with “no logging” if applicable. |
| ec2_securitygroup_default_restrict_traffic | cis_aws_ec2: deny when default SG has any allow rule | CIS; rationale. |
| ec2_securitygroup_allow_ingress_* (per-port checks) | One parameterized or multiple rules: allows_ssh, allows_rdp, allows_mysql, etc. from input_builder | India mapping; exact CLI per port. |
| ec2_securitygroup_not_used / from_launch_wizard | Optional (low): unused SG, launch-wizard SG | delete-security-group CLI. |
| ec2_networkacl_* | Omit in v1 if NACL not in fetcher; else india_aws_ec2 | When added: CERT-In network controls. |
| ec2_instance_public_ip | cis_aws_ec2 + india_aws_ec2: deny when has_public_ip true | DPDP/CERT-In; contextual severity; remediation. |
| ec2_instance_profile_attached | cis_aws_ec2: deny when instance has no instance profile | associate-iam-instance-profile CLI. |
| ec2_instance_port_*_exposed | Compound: instance has public IP and attached SG allows_ssh/allows_rdp/… | Critical; revoke on SG. |
| ec2_instance_secrets_user_data | india_aws_ec2: deny when user_data contains secret pattern (if available) | CERT-In; clear user data CLI. |
| ec2_launch_template_no_public_ip / imdsv2_required | cis_aws_ec2 (if we have launch template asset): deny when public IP or IMDSv1 | create-launch-template-version CLI. |
| ec2_instance (IMDSv2) | cis_aws_ec2: deny when imdsv2_required false (metadata_options.HttpTokens != required) | CIS + CERT-In; update-trail / instance attribute. |
| ec2_transitgateway_auto_accept_vpc_attachments | Optional: TGW auto-accept | modify-transit-gateway CLI. |

---

*Next: RDS, KMS, CloudTrail.*
