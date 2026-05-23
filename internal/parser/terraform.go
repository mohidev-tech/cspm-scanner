// Package parser turns Terraform .tf files into scanner.Resource values.
//
// The parser is intentionally simple — it understands top-level `resource`
// blocks and their literal attributes. Variable references, locals, and
// data sources are resolved as their literal source-text (e.g. "${var.foo}")
// because checks operate on what's *written*, not what's *evaluated*. That
// matches how tfsec, checkov, and trivy iac do it: catch the misconfiguration
// before plan time, not after.
package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/mohidev-tech/cspm-scanner/internal/scanner"
)

// ParsePath accepts a single .tf file or a directory of .tf files and
// returns every `resource` block found.
func ParsePath(path string) ([]scanner.Resource, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var files []string
	if info.IsDir() {
		err = filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !fi.IsDir() && strings.HasSuffix(p, ".tf") {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		files = []string{path}
	}

	parser := hclparse.NewParser()
	var out []scanner.Resource
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		file, diags := parser.ParseHCL(src, f)
		if diags.HasErrors() {
			return nil, fmt.Errorf("%s: %s", f, diags.Error())
		}
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, block := range body.Blocks {
			if block.Type != "resource" || len(block.Labels) < 2 {
				continue
			}
			out = append(out, scanner.Resource{
				Type:       block.Labels[0],
				Name:       block.Labels[1],
				File:       f,
				Line:       block.Range().Start.Line,
				Attributes: extractBody(block.Body),
			})
		}
	}
	return out, nil
}

// extractBody returns a map of attributes + nested block bodies. Values are
// the *literal source text* — checks see what the author wrote, not the
// evaluated plan. This is the conservative call: detect badness before it
// gets papered over by a variable file.
func extractBody(body *hclsyntax.Body) map[string]interface{} {
	out := map[string]interface{}{}
	for name, attr := range body.Attributes {
		out[name] = exprString(attr.Expr)
	}
	for _, b := range body.Blocks {
		nested := extractBody(b.Body)
		// Multiple blocks with the same type become a list (e.g. `ingress` blocks).
		if existing, ok := out[b.Type]; ok {
			switch v := existing.(type) {
			case []map[string]interface{}:
				out[b.Type] = append(v, nested)
			case map[string]interface{}:
				out[b.Type] = []map[string]interface{}{v, nested}
			}
		} else {
			out[b.Type] = nested
		}
	}
	return out
}

func exprString(e hcl.Expression) string {
	// Source-text fidelity: serialize whatever literal/reference is here.
	r := e.Range()
	src, err := os.ReadFile(r.Filename)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(src[r.Start.Byte:r.End.Byte]))
}
