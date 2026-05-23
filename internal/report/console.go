package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/mohidev-tech/cspm-scanner/internal/scanner"
)

// Console writes a human-readable summary. Color codes are honored when out
// is a terminal AND NO_COLOR is unset (respects the standard).
func Console(out io.Writer, color bool, findings []scanner.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(out, "no findings ✓")
		return
	}
	counts := map[scanner.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
		fmt.Fprintf(out, "%s %s\n", paint(color, f.Severity), f.Title)
		fmt.Fprintf(out, "  id:        %s\n", f.CheckID)
		fmt.Fprintf(out, "  resource:  %s.%s\n", f.Resource.Type, f.Resource.Name)
		fmt.Fprintf(out, "  location:  %s:%d\n", f.Resource.File, f.Resource.Line)
		fmt.Fprintf(out, "  why:       %s\n", f.Description)
		fmt.Fprintf(out, "  fix:       %s\n", f.Remediation)
		if len(f.Frameworks) > 0 {
			var fws []string
			for _, fw := range f.Frameworks {
				fws = append(fws, fw.Framework+" "+fw.Control)
			}
			fmt.Fprintf(out, "  maps to:   %s\n", strings.Join(fws, ", "))
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintf(out, "summary: %d findings  (CRITICAL=%d  HIGH=%d  MEDIUM=%d  LOW=%d)\n",
		len(findings),
		counts[scanner.SeverityCritical],
		counts[scanner.SeverityHigh],
		counts[scanner.SeverityMedium],
		counts[scanner.SeverityLow],
	)
}

func paint(on bool, s scanner.Severity) string {
	if !on {
		return "[" + s.String() + "]"
	}
	color := "\033[37m"
	switch s {
	case scanner.SeverityCritical:
		color = "\033[1;31m"
	case scanner.SeverityHigh:
		color = "\033[31m"
	case scanner.SeverityMedium:
		color = "\033[33m"
	case scanner.SeverityLow:
		color = "\033[36m"
	}
	return color + "[" + s.String() + "]\033[0m"
}
