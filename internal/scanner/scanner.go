package scanner

import "sort"

// Scanner runs a set of checks against a set of resources and returns the
// findings sorted by severity (desc) then check ID (asc) for stable output.
type Scanner struct {
	checks []Check
}

func New(checks []Check) *Scanner { return &Scanner{checks: checks} }

func (s *Scanner) Checks() []Check { return s.checks }

func (s *Scanner) Scan(resources []Resource) []Finding {
	out := make([]Finding, 0)
	for _, r := range resources {
		for _, c := range s.checks {
			if f := c.Evaluate(r); f != nil {
				out = append(out, *f)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].CheckID < out[j].CheckID
	})
	return out
}
