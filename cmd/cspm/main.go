package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mohidev-tech/cspm-scanner/internal/checks"
	"github.com/mohidev-tech/cspm-scanner/internal/parser"
	"github.com/mohidev-tech/cspm-scanner/internal/report"
	"github.com/mohidev-tech/cspm-scanner/internal/scanner"
)

// version is overridden via -ldflags at release time.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(cmdScan(os.Args[2:]))
	case "list-checks":
		os.Exit(cmdListChecks())
	case "version", "--version", "-v":
		fmt.Println("cspm-scanner", version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`cspm-scanner — IaC + cloud misconfig scanner with compliance mappings

Usage:
  cspm scan [flags] PATH         scan a .tf file or a directory of .tf files
  cspm list-checks               print every check + its compliance mapping
  cspm version

scan flags:
  --format string     output format: console (default), json, sarif
  --output string     write output to file instead of stdout
  --fail-on string    exit non-zero when a finding at this severity or worse is present
                      (CRITICAL|HIGH|MEDIUM|LOW, default HIGH)
  --no-color          disable color in console output

Examples:
  cspm scan ./infra/terraform
  cspm scan --format sarif --output cspm.sarif ./infra
  cspm scan --fail-on CRITICAL ./infra
`)
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	format := fs.String("format", "console", "console|json|sarif")
	out := fs.String("output", "", "write output to file instead of stdout")
	failOn := fs.String("fail-on", "HIGH", "CRITICAL|HIGH|MEDIUM|LOW")
	noColor := fs.Bool("no-color", false, "disable color in console output")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "scan requires exactly one PATH argument")
		return 2
	}

	resources, err := parser.ParsePath(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse error:", err)
		return 1
	}

	findings := scanner.New(checks.All()).Scan(resources)

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "write error:", err)
			return 1
		}
		defer f.Close()
		w = f
	}

	switch *format {
	case "console":
		report.Console(w, !*noColor && os.Getenv("NO_COLOR") == "" && *out == "", findings)
	case "json":
		if err := report.JSON(w, findings); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	case "sarif":
		if err := report.SARIF(w, version, findings); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown --format:", *format)
		return 2
	}

	threshold, ok := parseSeverity(*failOn)
	if !ok {
		fmt.Fprintln(os.Stderr, "invalid --fail-on:", *failOn)
		return 2
	}
	for _, f := range findings {
		if f.Severity >= threshold {
			return 1
		}
	}
	return 0
}

func cmdListChecks() int {
	for _, c := range checks.All() {
		fmt.Printf("%s  [%s]  %s\n", c.ID(), c.Severity(), c.Title())
		for _, fw := range c.Frameworks() {
			fmt.Printf("    %s %s\n", fw.Framework, fw.Control)
		}
	}
	return 0
}

func parseSeverity(s string) (scanner.Severity, bool) {
	switch s {
	case "CRITICAL":
		return scanner.SeverityCritical, true
	case "HIGH":
		return scanner.SeverityHigh, true
	case "MEDIUM":
		return scanner.SeverityMedium, true
	case "LOW":
		return scanner.SeverityLow, true
	}
	return 0, false
}
