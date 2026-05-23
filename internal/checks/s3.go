package checks

import (
	"strings"

	"github.com/mohidev-tech/cspm-scanner/internal/scanner"
)

// CSPM-AWS-S3-001 — S3 bucket without server-side encryption.
type S3Encryption struct{}

func (S3Encryption) ID() string             { return "CSPM-AWS-S3-001" }
func (S3Encryption) Title() string          { return "S3 bucket missing server-side encryption" }
func (S3Encryption) Severity() scanner.Severity { return scanner.SeverityHigh }
func (S3Encryption) Description() string {
	return "S3 buckets should encrypt objects at rest. Unencrypted buckets fail SOC2 CC6.7 and NIST SC-28."
}
func (S3Encryption) Remediation() string {
	return `Add an "aws_s3_bucket_server_side_encryption_configuration" resource for this bucket, or set the deprecated inline "server_side_encryption_configuration" block.`
}
func (S3Encryption) Frameworks() []scanner.FrameworkControl {
	return []scanner.FrameworkControl{
		{Framework: "SOC2", Control: "CC6.7"},
		{Framework: "NIST 800-53", Control: "SC-28"},
		{Framework: "CIS AWS", Control: "2.1.1"},
	}
}
func (c S3Encryption) Evaluate(r scanner.Resource) *scanner.Finding {
	if r.Type != "aws_s3_bucket" {
		return nil
	}
	if nestedBlock(r, "server_side_encryption_configuration") != nil {
		return nil
	}
	return finding(c, r, "no server_side_encryption_configuration block")
}

// CSPM-AWS-S3-002 — S3 bucket ACL public-read or public-read-write.
type S3PublicACL struct{}

func (S3PublicACL) ID() string             { return "CSPM-AWS-S3-002" }
func (S3PublicACL) Title() string          { return "S3 bucket has a public ACL" }
func (S3PublicACL) Severity() scanner.Severity { return scanner.SeverityCritical }
func (S3PublicACL) Description() string {
	return "Public S3 ACLs are the #1 cloud-misconfig data-breach pattern. Block them at the bucket and account level."
}
func (S3PublicACL) Remediation() string {
	return `Set acl = "private" and pair with an "aws_s3_bucket_public_access_block" with all four flags = true.`
}
func (S3PublicACL) Frameworks() []scanner.FrameworkControl {
	return []scanner.FrameworkControl{
		{Framework: "SOC2", Control: "CC6.1"},
		{Framework: "NIST 800-53", Control: "AC-3"},
		{Framework: "CIS AWS", Control: "2.1.5"},
	}
}
func (c S3PublicACL) Evaluate(r scanner.Resource) *scanner.Finding {
	if r.Type != "aws_s3_bucket" {
		return nil
	}
	acl := strings.Trim(attr(r, "acl"), `"`)
	if acl == "public-read" || acl == "public-read-write" {
		return finding(c, r, "acl = "+acl)
	}
	return nil
}
