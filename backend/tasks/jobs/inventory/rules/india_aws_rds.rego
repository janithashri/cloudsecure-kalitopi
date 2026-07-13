# CloudSecure India compliance — RDS (DPDP 2023, CERT-In 2022, RBI)
# Same resource type as cis_aws_rds; India-specific mappings.

package cloudsecure.rules.india_aws_rds

import rego.v1

default allow := true

# ---------------------------------------------------------------------------
# DPDP / CERT-In: RDS publicly accessible
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "rds_instance"
	input.asset.publicly_accessible == true
	msg := {
		"rule_id": "DPDP-RDS-PUBLIC",
		"issue": sprintf("RDS instance '%v' is publicly accessible — DPDP and CERT-In require restricting data access", [input.asset.db_identifier]),
		"severity": "CRITICAL",
		"framework": "DPDP Act 2023",
		"section": "Section 8 - Security",
		"status": "FAIL",
		"compliance": ["DPDP 2023 S.8", "CERT-In 2022", "RBI"],
		"remediation": sprintf("aws rds modify-db-instance --db-instance-identifier %v --no-publicly-accessible --apply-immediately", [input.asset.db_identifier]),
	}
}

# ---------------------------------------------------------------------------
# RBI / DPDP: Storage encryption
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "rds_instance"
	not input.asset.storage_encrypted
	msg := {
		"rule_id": "RBI-RDS-ENCRYPT",
		"issue": sprintf("RDS instance '%v' storage is not encrypted — RBI and DPDP require encryption of sensitive data", [input.asset.db_identifier]),
		"severity": "HIGH",
		"framework": "RBI Cyber Security Framework",
		"section": "Data Protection",
		"status": "FAIL",
		"compliance": ["RBI", "DPDP 2023", "CERT-In 2022"],
		"remediation": "Create a new encrypted RDS instance and migrate; or use snapshot copy with KMS encryption",
	}
}

# ---------------------------------------------------------------------------
# CERT-In: Deletion protection
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "rds_instance"
	not input.asset.deletion_protection
	msg := {
		"rule_id": "CERT-In-RDS-DELETE",
		"issue": sprintf("RDS instance '%v' does not have deletion protection — CERT-In recommends safeguards against accidental deletion", [input.asset.db_identifier]),
		"severity": "MEDIUM",
		"framework": "CERT-In 2022",
		"section": "Incident Prevention",
		"status": "FAIL",
		"compliance": ["CERT-In 2022", "RBI"],
		"remediation": sprintf("aws rds modify-db-instance --db-instance-identifier %v --deletion-protection --apply-immediately", [input.asset.db_identifier]),
	}
}

# ---------------------------------------------------------------------------
# RBI: Backup retention
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "rds_instance"
	input.asset.backup_retention == 0
	msg := {
		"rule_id": "RBI-RDS-BACKUP",
		"issue": sprintf("RDS instance '%v' has no automated backup retention — RBI requires backup and recovery capability", [input.asset.db_identifier]),
		"severity": "HIGH",
		"framework": "RBI Cyber Security Framework",
		"section": "Backup and Recovery",
		"status": "FAIL",
		"compliance": ["RBI", "DPDP 2023", "CERT-In 2022"],
		"remediation": sprintf("aws rds modify-db-instance --db-instance-identifier %v --backup-retention-period 7 --apply-immediately", [input.asset.db_identifier]),
	}
}

# ---------------------------------------------------------------------------
# RDS in VPC
# ---------------------------------------------------------------------------
deny contains msg if {
	input.asset.asset_type == "rds_instance"
	input.asset.inside_vpc == false
	msg := {
		"rule_id": "CERT-In-RDS-VPC",
		"issue": sprintf("RDS instance '%v' is not in a VPC — CERT-In recommends network isolation", [input.asset.db_identifier]),
		"severity": "HIGH",
		"framework": "CERT-In 2022",
		"section": "Network Security",
		"status": "FAIL",
		"compliance": ["CERT-In 2022", "RBI"],
		"remediation": "Modify DB instance to use a DB subnet group in a VPC",
	}
}
