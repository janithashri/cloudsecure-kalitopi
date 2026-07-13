# CloudSecure CIS AWS Foundations Benchmark — RDS
# Prowler reference: providers/aws/services/rds/
# Input: input.asset (asset_type: "rds_instance")

package cloudsecure.rules.cis_aws_rds

import rego.v1

default allow := true

# ---------------------------------------------------------------------------
# RDS publicly accessible
# Real-world impact: Public RDS instances are exposed to internet-based attacks and data theft.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "rds_instance"
	input.asset.publicly_accessible == true
	msg := {
		"rule_id": "CIS-4.3.1",
		"issue": sprintf("RDS instance '%v' in region '%v' is publicly accessible", [input.asset.db_identifier, input.asset.region]),
		"severity": severity_rds_public,
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Database Services",
		"status": "FAIL",
		"compliance": ["CIS 4.3.1", "DPDP 2023", "CERT-In 2022", "RBI"],
		"remediation": sprintf("aws rds modify-db-instance --db-instance-identifier %v --no-publicly-accessible --apply-immediately", [input.asset.db_identifier]),
	}
}

severity_rds_public := "CRITICAL" if {
	input.asset.tags.environment == "production"
} else := "HIGH"

# ---------------------------------------------------------------------------
# RDS storage encryption
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "rds_instance"
	not input.asset.storage_encrypted
	msg := {
		"rule_id": "CIS-4.3.2",
		"issue": sprintf("RDS instance '%v' does not have storage encryption enabled", [input.asset.db_identifier]),
		"severity": severity_rds_encryption,
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Database Services",
		"status": "FAIL",
		"compliance": ["CIS 4.3.2", "DPDP 2023", "RBI", "CERT-In 2022"],
		"remediation": "Storage encryption cannot be enabled on an existing instance. Create a new encrypted instance and migrate data, or use a snapshot copy with encryption",
	}
}

severity_rds_encryption := "HIGH" if {
	input.asset.tags.environment == "production"
} else := "MEDIUM"

# ---------------------------------------------------------------------------
# RDS Multi-AZ
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "rds_instance"
	not input.asset.multi_az
	msg := {
		"rule_id": "CIS-4.3.3",
		"issue": sprintf("RDS instance '%v' is not configured for Multi-AZ deployment", [input.asset.db_identifier]),
		"severity": "MEDIUM",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Database Services",
		"status": "FAIL",
		"compliance": ["CIS 4.3.3", "RBI"],
		"remediation": sprintf("aws rds modify-db-instance --db-instance-identifier %v --multi-az --apply-immediately", [input.asset.db_identifier]),
	}
}

# ---------------------------------------------------------------------------
# RDS deletion protection
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "rds_instance"
	not input.asset.deletion_protection
	msg := {
		"rule_id": "CIS-4.3.4",
		"issue": sprintf("RDS instance '%v' does not have deletion protection enabled", [input.asset.db_identifier]),
		"severity": "MEDIUM",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Database Services",
		"status": "FAIL",
		"compliance": ["CIS 4.3.4", "CERT-In 2022"],
		"remediation": sprintf("aws rds modify-db-instance --db-instance-identifier %v --deletion-protection --apply-immediately", [input.asset.db_identifier]),
	}
}

# ---------------------------------------------------------------------------
# RDS backup retention (minimum 1 day for automated backups)
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "rds_instance"
	input.asset.backup_retention == 0
	msg := {
		"rule_id": "CIS-4.3.5",
		"issue": sprintf("RDS instance '%v' has backup retention period set to 0 (automated backups disabled)", [input.asset.db_identifier]),
		"severity": "HIGH",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Database Services",
		"status": "FAIL",
		"compliance": ["CIS 4.3.5", "RBI", "DPDP 2023"],
		"remediation": sprintf("aws rds modify-db-instance --db-instance-identifier %v --backup-retention-period 7 --apply-immediately", [input.asset.db_identifier]),
	}
}

# ---------------------------------------------------------------------------
# RDS auto minor version upgrade
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "rds_instance"
	not input.asset.auto_minor_upgrade
	msg := {
		"rule_id": "CIS-4.3.6",
		"issue": sprintf("RDS instance '%v' does not have auto minor version upgrade enabled", [input.asset.db_identifier]),
		"severity": "MEDIUM",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Database Services",
		"status": "FAIL",
		"compliance": ["CIS 4.3.6", "CERT-In 2022"],
		"remediation": sprintf("aws rds modify-db-instance --db-instance-identifier %v --auto-minor-version-upgrade --apply-immediately", [input.asset.db_identifier]),
	}
}

# ---------------------------------------------------------------------------
# RDS in VPC (subnet group present)
# Fires when input_builder sets inside_vpc to false (e.g. from missing DBSubnetGroup or VpcSecurityGroups).
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "rds_instance"
	input.asset.inside_vpc == false
	msg := {
		"rule_id": "CIS-4.3.7",
		"issue": sprintf("RDS instance '%v' is not in a VPC (EC2-Classic or missing subnet group)", [input.asset.db_identifier]),
		"severity": "HIGH",
		"framework": "CIS AWS Foundations Benchmark v2.0",
		"section": "4 Database Services",
		"status": "FAIL",
		"compliance": ["CIS 4.3.7", "CERT-In 2022"],
		"remediation": sprintf("aws rds modify-db-instance --db-instance-identifier %v --db-subnet-group-name <subnet_group> --apply-immediately", [input.asset.db_identifier]),
	}
}
