package checks

import (
	"strings"

	"github.com/mohidev-tech/cspm-scanner/internal/scanner"
)

// CSPM-AWS-IAM-001 — IAM policy document with Action="*" or Resource="*" on Allow.
//
// We match on the *literal* policy document text because the policy attribute
// is almost always a heredoc or jsonencode() that we don't want to evaluate.
// Catches the classic "I'll tighten this later" mistake.
type IAMWildcard struct{}

func (IAMWildcard) ID() string             { return "CSPM-AWS-IAM-001" }
func (IAMWildcard) Title() string          { return "IAM policy grants wildcard permissions" }
func (IAMWildcard) Severity() scanner.Severity { return scanner.SeverityHigh }
func (IAMWildcard) Description() string {
	return `IAM policies with "Action": "*" or "Resource": "*" on Allow statements violate least-privilege. They also fail SOC2 logical-access controls under audit.`
}
func (IAMWildcard) Remediation() string {
	return "Replace wildcards with the specific Actions and resource ARNs the principal actually needs. Use IAM Access Analyzer to right-size."
}
func (IAMWildcard) Frameworks() []scanner.FrameworkControl {
	return []scanner.FrameworkControl{
		{Framework: "SOC2", Control: "CC6.1"},
		{Framework: "NIST 800-53", Control: "AC-6"},
		{Framework: "CIS AWS", Control: "1.16"},
	}
}
func (c IAMWildcard) Evaluate(r scanner.Resource) *scanner.Finding {
	if r.Type != "aws_iam_policy" && r.Type != "aws_iam_role_policy" {
		return nil
	}
	doc := attr(r, "policy")
	// Look for Allow + "*" within ~150 chars of each other. Cheap heuristic;
	// not airtight, but covers the dominant footgun in practice.
	if !strings.Contains(doc, `"Effect": "Allow"`) && !strings.Contains(doc, `"Effect":"Allow"`) {
		return nil
	}
	for _, key := range []string{`"Action": "*"`, `"Action":"*"`, `"Resource": "*"`, `"Resource":"*"`} {
		if strings.Contains(doc, key) {
			return finding(c, r, "policy document contains "+key+" on an Allow effect")
		}
	}
	return nil
}
