package checks

import (
	"strings"

	"github.com/mohidev-tech/cspm-scanner/internal/scanner"
)

// CSPM-AWS-EC2-001 — Security group allows 0.0.0.0/0 ingress on SSH/RDP.
type SGOpenAdminPort struct{}

func (SGOpenAdminPort) ID() string             { return "CSPM-AWS-EC2-001" }
func (SGOpenAdminPort) Title() string          { return "Security group exposes admin port to the internet" }
func (SGOpenAdminPort) Severity() scanner.Severity { return scanner.SeverityCritical }
func (SGOpenAdminPort) Description() string {
	return "Security groups allowing 0.0.0.0/0 on SSH (22) or RDP (3389) put admin interfaces directly on the internet. Brute-force attempts begin within minutes of exposure."
}
func (SGOpenAdminPort) Remediation() string {
	return "Restrict ingress to a VPN/bastion CIDR or use Systems Manager Session Manager for shell access."
}
func (SGOpenAdminPort) Frameworks() []scanner.FrameworkControl {
	return []scanner.FrameworkControl{
		{Framework: "SOC2", Control: "CC6.6"},
		{Framework: "NIST 800-53", Control: "AC-4"},
		{Framework: "CIS AWS", Control: "5.2"},
	}
}
func (c SGOpenAdminPort) Evaluate(r scanner.Resource) *scanner.Finding {
	if r.Type != "aws_security_group" {
		return nil
	}
	for _, ing := range nestedBlocks(r, "ingress") {
		cidrs := nestedAttr(ing, "cidr_blocks")
		if !strings.Contains(cidrs, "0.0.0.0/0") {
			continue
		}
		from := nestedAttr(ing, "from_port")
		to := nestedAttr(ing, "to_port")
		if portInRange(from, to, 22) || portInRange(from, to, 3389) {
			return finding(c, r, "ingress block opens admin port to 0.0.0.0/0 (from="+from+" to="+to+")")
		}
	}
	return nil
}

func portInRange(from, to string, p int) bool {
	// Literal-text comparison is fine for the common cases: from_port = 22, to_port = 22.
	// Variable refs are treated as not-matching (conservative — better to miss than false-positive).
	tgt := itoa(p)
	if from == tgt && to == tgt {
		return true
	}
	// Range: from_port = 0, to_port = 65535
	if from == "0" && (to == "65535" || to == "65536") {
		return true
	}
	return false
}

func itoa(p int) string {
	if p == 0 {
		return "0"
	}
	digits := []byte{}
	for p > 0 {
		digits = append([]byte{byte('0' + p%10)}, digits...)
		p /= 10
	}
	return string(digits)
}
