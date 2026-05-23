package checks

import "github.com/mohidev-tech/cspm-scanner/internal/scanner"

// CSPM-AWS-RDS-001 — RDS instance publicly accessible.
type RDSPublic struct{}

func (RDSPublic) ID() string             { return "CSPM-AWS-RDS-001" }
func (RDSPublic) Title() string          { return "RDS instance is publicly accessible" }
func (RDSPublic) Severity() scanner.Severity { return scanner.SeverityHigh }
func (RDSPublic) Description() string {
	return "RDS instances with publicly_accessible=true sit on a public IP. Combined with a permissive SG, this exposes the database directly to the internet."
}
func (RDSPublic) Remediation() string {
	return "Set publicly_accessible = false and place the RDS subnet group in private subnets. Use a VPN/PrivateLink for operator access."
}
func (RDSPublic) Frameworks() []scanner.FrameworkControl {
	return []scanner.FrameworkControl{
		{Framework: "SOC2", Control: "CC6.6"},
		{Framework: "NIST 800-53", Control: "SC-7"},
		{Framework: "CIS AWS", Control: "2.3.3"},
	}
}
func (c RDSPublic) Evaluate(r scanner.Resource) *scanner.Finding {
	if r.Type != "aws_db_instance" {
		return nil
	}
	if attrBool(r, "publicly_accessible") {
		return finding(c, r, "publicly_accessible = true")
	}
	return nil
}

// CSPM-AWS-RDS-002 — RDS instance without storage encryption.
type RDSUnencrypted struct{}

func (RDSUnencrypted) ID() string             { return "CSPM-AWS-RDS-002" }
func (RDSUnencrypted) Title() string          { return "RDS instance storage not encrypted" }
func (RDSUnencrypted) Severity() scanner.Severity { return scanner.SeverityHigh }
func (RDSUnencrypted) Description() string {
	return "RDS storage_encrypted defaults to false. Backups, snapshots, and replicas inherit the same plaintext-at-rest state."
}
func (RDSUnencrypted) Remediation() string {
	return "Set storage_encrypted = true and choose a kms_key_id (or accept the AWS-managed default)."
}
func (RDSUnencrypted) Frameworks() []scanner.FrameworkControl {
	return []scanner.FrameworkControl{
		{Framework: "SOC2", Control: "CC6.7"},
		{Framework: "NIST 800-53", Control: "SC-28"},
		{Framework: "CIS AWS", Control: "2.3.1"},
	}
}
func (c RDSUnencrypted) Evaluate(r scanner.Resource) *scanner.Finding {
	if r.Type != "aws_db_instance" {
		return nil
	}
	if !attrBool(r, "storage_encrypted") {
		return finding(c, r, "storage_encrypted is not true")
	}
	return nil
}
