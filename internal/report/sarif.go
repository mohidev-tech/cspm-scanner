package report

import (
	"encoding/json"
	"io"

	"github.com/mohidev-tech/cspm-scanner/internal/scanner"
)

// SARIF v2.1.0 output. Upload to GitHub Code Scanning via
// github/codeql-action/upload-sarif and findings appear in the Security tab.

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string       `json:"name"`
	Version        string       `json:"version"`
	InformationURI string       `json:"informationUri"`
	Rules          []sarifRule  `json:"rules"`
}
type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription sarifMultiformatString `json:"shortDescription"`
	FullDescription  sarifMultiformatString `json:"fullDescription"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	DefaultConfig    sarifConfig            `json:"defaultConfiguration"`
}
type sarifConfig struct {
	Level string `json:"level"`
}
type sarifMultiformatString struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMultiformatString `json:"message"`
	Locations []sarifLocation `json:"locations"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}
type sarifArtifactLocation struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func SARIF(out io.Writer, version string, findings []scanner.Finding) error {
	// One rule per unique check; SARIF dedups them in the UI.
	rulesByID := map[string]sarifRule{}
	for _, f := range findings {
		if _, ok := rulesByID[f.CheckID]; ok {
			continue
		}
		rulesByID[f.CheckID] = sarifRule{
			ID:               f.CheckID,
			Name:             f.Title,
			ShortDescription: sarifMultiformatString{Text: f.Title},
			FullDescription:  sarifMultiformatString{Text: f.Description},
			DefaultConfig:    sarifConfig{Level: sarifLevel(f.Severity)},
		}
	}
	rules := make([]sarifRule, 0, len(rulesByID))
	for _, r := range rulesByID {
		rules = append(rules, r)
	}

	results := make([]sarifResult, len(findings))
	for i, f := range findings {
		results[i] = sarifResult{
			RuleID:  f.CheckID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMultiformatString{Text: f.Description},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.Resource.File},
					Region:           sarifRegion{StartLine: f.Resource.Line},
				},
			}},
		}
	}

	r := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "cspm-scanner",
				Version:        version,
				InformationURI: "https://github.com/mohidev-tech/cspm-scanner",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func sarifLevel(s scanner.Severity) string {
	switch s {
	case scanner.SeverityCritical, scanner.SeverityHigh:
		return "error"
	case scanner.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
