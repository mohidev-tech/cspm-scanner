package report

import (
	"encoding/json"
	"io"

	"github.com/mohidev-tech/cspm-scanner/internal/scanner"
)

type jsonFinding struct {
	ID          string                      `json:"id"`
	Title       string                      `json:"title"`
	Severity    string                      `json:"severity"`
	Description string                      `json:"description"`
	Remediation string                      `json:"remediation"`
	Resource    jsonResource                `json:"resource"`
	Frameworks  []scanner.FrameworkControl  `json:"frameworks"`
}

type jsonResource struct {
	Type string `json:"type"`
	Name string `json:"name"`
	File string `json:"file"`
	Line int    `json:"line"`
}

// JSON writes a stable JSON array — easy to pipe into jq, store in CI artifacts,
// or feed to a custom dashboard.
func JSON(out io.Writer, findings []scanner.Finding) error {
	rows := make([]jsonFinding, len(findings))
	for i, f := range findings {
		rows[i] = jsonFinding{
			ID:          f.CheckID,
			Title:       f.Title,
			Severity:    f.Severity.String(),
			Description: f.Description,
			Remediation: f.Remediation,
			Resource: jsonResource{
				Type: f.Resource.Type,
				Name: f.Resource.Name,
				File: f.Resource.File,
				Line: f.Resource.Line,
			},
			Frameworks: f.Frameworks,
		}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}
