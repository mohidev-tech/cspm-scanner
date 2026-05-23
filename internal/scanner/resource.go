// Package scanner defines the core Resource model and orchestrates checks.
package scanner

// Resource is the normalized shape every check sees, regardless of input
// format (HCL files, terraform plan JSON, live cloud API). Keeping checks
// decoupled from the parser means adding new sources (e.g. CloudFormation,
// Pulumi YAML) is a parser problem, not a checks problem.
type Resource struct {
	Type       string                 // e.g. "aws_s3_bucket"
	Name       string                 // local name in the IaC, e.g. "logs"
	File       string                 // source file path
	Line       int                    // start line in source
	Attributes map[string]interface{} // top-level args + nested blocks
}

// Severity ranks findings.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	return [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}[s]
}

// Finding is what a check returns when a Resource violates it.
type Finding struct {
	CheckID     string
	Title       string
	Severity    Severity
	Resource    Resource
	Description string
	Remediation string
	Frameworks  []FrameworkControl
}

// FrameworkControl is one row in the compliance mapping table.
type FrameworkControl struct {
	Framework string // "SOC2", "NIST 800-53", "CIS AWS"
	Control   string // e.g. "CC6.1", "SC-28", "2.1.5"
}

// Check is the boundary between the engine and individual rules. Pure
// function: same Resource always yields the same Finding-or-nil. No I/O.
type Check interface {
	ID() string
	Title() string
	Severity() Severity
	Frameworks() []FrameworkControl
	Description() string
	Remediation() string
	Evaluate(r Resource) *Finding
}
