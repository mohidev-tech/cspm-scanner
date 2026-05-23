package checks

import "github.com/mohidev-tech/cspm-scanner/internal/scanner"

// All returns every check shipped with the scanner. Adding a new check is one
// line here plus a new file.
func All() []scanner.Check {
	return []scanner.Check{
		S3Encryption{},
		S3PublicACL{},
		SGOpenAdminPort{},
		RDSPublic{},
		RDSUnencrypted{},
		IAMWildcard{},
	}
}

// finding is the shared finding-builder so every check produces a consistent
// shape. The variadic detail line shows up in the console reporter.
func finding(c scanner.Check, r scanner.Resource, detail string) *scanner.Finding {
	return &scanner.Finding{
		CheckID:     c.ID(),
		Title:       c.Title(),
		Severity:    c.Severity(),
		Resource:    r,
		Description: c.Description() + " — " + detail,
		Remediation: c.Remediation(),
		Frameworks:  c.Frameworks(),
	}
}
