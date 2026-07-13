# CloudSecure CIS AWS Foundations Benchmark — EC2 (Security Groups & Instances)
# Prowler reference: providers/aws/services/ec2/
# Input: input.asset (asset_type: "security_group" or "ec2_instance")

package cloudsecure.rules.cis_aws_ec2

import rego.v1

default allow := true

# ---------------------------------------------------------------------------
# Security group: all ports open to 0.0.0.0/0 or ::/0
# Real-world impact: Wide-open SGs are the primary vector for brute-force and ransomware.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "security_group"
	input.asset.allows_all_ingress
	msg := {
		"rule_id": "CIS-4.1.1",
		"issue": sprintf("Security group '%v' (%v) allows all inbound traffic from 0.0.0.0/0 or ::/0", [input.asset.group_name, input.asset.group_id]),
		"severity": severity_sg_open,
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Networking",
		"status": "FAIL",
		"compliance": ["CIS 4.1", "CERT-In 2022", "DPDP 2023"],
		"remediation": sprintf("Revoke overly permissive rules: aws ec2 revoke-security-group-ingress --group-id %v --protocol all --cidr 0.0.0.0/0 (and ::/0 if present)", [input.asset.group_id]),
	}
}

severity_sg_open := "CRITICAL" if {
	input.asset.tags.environment == "production"
} else := "HIGH"

# ---------------------------------------------------------------------------
# SSH (port 22) from internet
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "security_group"
	input.asset.allows_ssh
	msg := {
		"rule_id": "CIS-4.1.2",
		"issue": sprintf("Security group '%v' (%v) allows SSH (TCP 22) from 0.0.0.0/0 or ::/0", [input.asset.group_name, input.asset.group_id]),
		"severity": "HIGH",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Networking",
		"status": "FAIL",
		"compliance": ["CIS 4.1.2", "CERT-In 2022"],
		"remediation": sprintf("aws ec2 revoke-security-group-ingress --group-id %v --protocol tcp --port 22 --cidr 0.0.0.0/0", [input.asset.group_id]),
	}
}

# ---------------------------------------------------------------------------
# RDP (port 3389) from internet
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "security_group"
	input.asset.allows_rdp
	msg := {
		"rule_id": "CIS-4.1.3",
		"issue": sprintf("Security group '%v' (%v) allows RDP (TCP 3389) from 0.0.0.0/0 or ::/0", [input.asset.group_name, input.asset.group_id]),
		"severity": "HIGH",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Networking",
		"status": "FAIL",
		"compliance": ["CIS 4.1.3", "CERT-In 2022"],
		"remediation": sprintf("aws ec2 revoke-security-group-ingress --group-id %v --protocol tcp --port 3389 --cidr 0.0.0.0/0", [input.asset.group_id]),
	}
}

# ---------------------------------------------------------------------------
# Default security group should not allow traffic
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "security_group"
	input.asset.group_name == "default"
	count(input.asset.inbound_rules) > 0
	msg := {
		"rule_id": "CIS-4.2",
		"issue": sprintf("Default security group '%v' in VPC has inbound rules — should restrict all traffic", [input.asset.group_id]),
		"severity": "HIGH",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Networking",
		"status": "FAIL",
		"compliance": ["CIS 4.2", "CERT-In 2022"],
		"remediation": "Remove all inbound rules from the default security group in the VPC",
	}
}

# ---------------------------------------------------------------------------
# EC2 instance: IMDSv2 required (metadata service)
# Real-world impact: IMDSv1 allows SSRF and credential theft; IMDSv2 requires session-oriented requests.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "ec2_instance"
	not input.asset.imdsv2_required
	msg := {
		"rule_id": "CIS-4.1.4",
		"issue": sprintf("EC2 instance '%v' in region '%v' does not require IMDSv2 — metadata API is vulnerable to SSRF", [input.asset.instance_id, input.asset.region]),
		"severity": "HIGH",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Networking",
		"status": "FAIL",
		"compliance": ["CIS 4.1.4", "CERT-In 2022"],
		"remediation": sprintf("aws ec2 modify-instance-metadata-options --instance-id %v --http-tokens required --http-put-response-hop-limit 2", [input.asset.instance_id]),
	}
}

# ---------------------------------------------------------------------------
# EC2 instance: public IP on instance
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "ec2_instance"
	input.asset.has_public_ip
	msg := {
		"rule_id": "CIS-4.1.5",
		"issue": sprintf("EC2 instance '%v' has a public IP address — prefer private access (e.g. SSM, VPN)", [input.asset.instance_id]),
		"severity": severity_public_ip,
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Networking",
		"status": "FAIL",
		"compliance": ["CIS 4.1.5", "DPDP 2023", "CERT-In 2022"],
		"remediation": "Use a private subnet and disable auto-assign public IP for the instance; use AWS Systems Manager Session Manager for access",
	}
}

severity_public_ip := "HIGH" if {
	input.asset.tags.environment == "production"
} else := "MEDIUM"

# ---------------------------------------------------------------------------
# EC2 instance: no IAM instance profile
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "ec2_instance"
	not input.asset.iam_instance_profile_attached
	msg := {
		"rule_id": "CIS-4.1.6",
		"issue": sprintf("EC2 instance '%v' does not have an IAM instance profile attached", [input.asset.instance_id]),
		"severity": "MEDIUM",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Networking",
		"status": "FAIL",
		"compliance": ["CIS 4.1.6", "CERT-In 2022"],
		"remediation": sprintf("aws ec2 associate-iam-instance-profile --instance-id %v --iam-instance-profile Name=<PROFILE_NAME>", [input.asset.instance_id]),
	}
}

# ---------------------------------------------------------------------------
# High-risk TCP ports from internet (3306, 5432, 6379, 1433, 27017, etc.)
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "security_group"
	input.asset.allows_high_risk_ports
	msg := {
		"rule_id": "CIS-4.1.7",
		"issue": sprintf("Security group '%v' allows high-risk database/management ports (e.g. 3306, 5432, 6379) from the internet", [input.asset.group_id]),
		"severity": "HIGH",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Networking",
		"status": "FAIL",
		"compliance": ["CIS 4.1", "CERT-In 2022", "DPDP 2023"],
		"remediation": "Revoke ingress rules for MySQL (3306), PostgreSQL (5432), Redis (6379), MSSQL (1433), MongoDB (27017), etc. from 0.0.0.0/0; restrict to VPC or VPN",
	}
}

# ---------------------------------------------------------------------------
# Unrestricted outbound (optional — often required for updates)
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "security_group"
	input.asset.allows_all_egress
	msg := {
		"rule_id": "CIS-4.1-EGRESS",
		"issue": sprintf("Security group '%v' allows all outbound traffic (0.0.0.0/0) — consider restricting egress where possible", [input.asset.group_id]),
		"severity": "LOW",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Networking",
		"status": "FAIL",
		"compliance": ["CIS 4.1"],
		"remediation": "Add egress rules that allow only required destinations (e.g. HTTPS 443, NTP) and remove 0.0.0.0/0 if not needed",
	}
}
