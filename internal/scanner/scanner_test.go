package scanner_test

import (
	"path/filepath"
	"testing"

	"github.com/mohidev-tech/cspm-scanner/internal/checks"
	"github.com/mohidev-tech/cspm-scanner/internal/parser"
	"github.com/mohidev-tech/cspm-scanner/internal/scanner"
)

func TestBadFixture_FindsAllExpectedChecks(t *testing.T) {
	resources, err := parser.ParsePath(filepath.Join("..", "..", "testdata", "bad"))
	if err != nil {
		t.Fatal(err)
	}
	findings := scanner.New(checks.All()).Scan(resources)

	want := map[string]bool{
		"CSPM-AWS-S3-002":  false, // public ACL
		"CSPM-AWS-EC2-001": false, // SG 22 open
		"CSPM-AWS-RDS-001": false, // publicly_accessible
		"CSPM-AWS-RDS-002": false, // not encrypted
		"CSPM-AWS-IAM-001": false, // wildcard
		"CSPM-AWS-S3-001":  false, // no SSE block (also true for bad bucket)
	}
	for _, f := range findings {
		if _, ok := want[f.CheckID]; ok {
			want[f.CheckID] = true
		}
	}
	for id, got := range want {
		if !got {
			t.Errorf("expected check %s to fire on testdata/bad, did not", id)
		}
	}
	t.Logf("got %d findings", len(findings))
}

func TestGoodFixture_NoFindings(t *testing.T) {
	resources, err := parser.ParsePath(filepath.Join("..", "..", "testdata", "good"))
	if err != nil {
		t.Fatal(err)
	}
	findings := scanner.New(checks.All()).Scan(resources)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on testdata/good, got %d:", len(findings))
		for _, f := range findings {
			t.Errorf("  %s on %s.%s", f.CheckID, f.Resource.Type, f.Resource.Name)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	resources, _ := parser.ParsePath(filepath.Join("..", "..", "testdata", "bad"))
	findings := scanner.New(checks.All()).Scan(resources)
	for i := 1; i < len(findings); i++ {
		if findings[i-1].Severity < findings[i].Severity {
			t.Fatalf("findings not sorted by severity desc: %v before %v",
				findings[i-1].Severity, findings[i].Severity)
		}
	}
}
