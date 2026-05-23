# Adding a new check

A walk-through. Same content as [CONTRIBUTING.md](../CONTRIBUTING.md), expanded with one fully-worked example.

## Worked example — detect Lambda function URLs with no auth

`aws_lambda_function_url` creates a public HTTPS endpoint for a Lambda. When `authorization_type = "NONE"`, the endpoint is open to the internet. CIS AWS Foundations doesn't have a control for this yet; SOC2 maps it under CC6.6 ("Logical access — perimeter").

### 1. Pick an ID

```
$ cspm list-checks
CSPM-AWS-S3-001  [HIGH]      ...
CSPM-AWS-S3-002  [CRITICAL]  ...
CSPM-AWS-EC2-001 [CRITICAL]  ...
CSPM-AWS-RDS-001 [HIGH]      ...
CSPM-AWS-RDS-002 [HIGH]      ...
CSPM-AWS-IAM-001 [HIGH]      ...
```

Next free Lambda ID: `CSPM-AWS-LAMBDA-001`.

### 2. Create the check file

`internal/checks/lambda.go`:

```go
package checks

import "github.com/mohidev-tech/cspm-scanner/internal/scanner"

type LambdaPublicURL struct{}

func (LambdaPublicURL) ID() string             { return "CSPM-AWS-LAMBDA-001" }
func (LambdaPublicURL) Title() string          { return "Lambda function URL has no auth" }
func (LambdaPublicURL) Severity() scanner.Severity { return scanner.SeverityHigh }
func (LambdaPublicURL) Description() string {
	return "aws_lambda_function_url with authorization_type=NONE creates an unauthenticated public HTTPS endpoint. Anyone on the internet can invoke it."
}
func (LambdaPublicURL) Remediation() string {
	return `Set authorization_type = "AWS_IAM" and front the URL with a known caller principal, or remove the URL and invoke the function via API Gateway with an authorizer.`
}
func (LambdaPublicURL) Frameworks() []scanner.FrameworkControl {
	return []scanner.FrameworkControl{
		{Framework: "SOC2",        Control: "CC6.6"},
		{Framework: "NIST 800-53", Control: "AC-3"},
	}
}
func (c LambdaPublicURL) Evaluate(r scanner.Resource) *scanner.Finding {
	if r.Type != "aws_lambda_function_url" {
		return nil
	}
	if attr(r, "authorization_type") == `"NONE"` {
		return finding(c, r, `authorization_type = "NONE"`)
	}
	return nil
}
```

### 3. Register

`internal/checks/registry.go`:

```go
func All() []scanner.Check {
	return []scanner.Check{
		S3Encryption{}, S3PublicACL{},
		SGOpenAdminPort{},
		RDSPublic{}, RDSUnencrypted{},
		IAMWildcard{},
		LambdaPublicURL{},  // ← new
	}
}
```

### 4. Fixtures

`testdata/bad/lambda.tf` — should fire:

```hcl
resource "aws_lambda_function_url" "open" {
  function_name      = "my-func"
  authorization_type = "NONE"
}
```

`testdata/good/lambda.tf` — should NOT fire:

```hcl
resource "aws_lambda_function_url" "closed" {
  function_name      = "my-func"
  authorization_type = "AWS_IAM"
}
```

### 5. Tests

```bash
go test -race ./...
```

The existing `internal/scanner/scanner_test.go` will:

- Scan `testdata/good/` — must return zero findings (catches false positives).
- Scan `testdata/bad/` — must include `CSPM-AWS-LAMBDA-001` (catches false negatives).

If both pass, open a PR. Update the **What it catches** table in [README.md](../README.md) to include the new row, and you're done.

## Tips

- **The `attr()` helper returns the literal source text.** That's `"NONE"` (with quotes), not `NONE`. Match strings accordingly — see how the example compares against `` `"NONE"` `` rather than `"NONE"`.
- **For nested blocks** (e.g. `ingress`, `lifecycle_rule`, `server_side_encryption_configuration`), use `nestedBlock(r, "ingress")` for a single occurrence or `nestedBlocks(r, "ingress")` for a slice when the block can repeat.
- **For variable references** (`var.foo`, `local.bar`), `attr()` returns the literal `var.foo` source text. **Don't fire** in this case — that's a false positive. Compare against expected literal values only.
- **Severity guide:**
  - `CRITICAL` — literally a data-breach pattern (public S3, SSH open to internet).
  - `HIGH` — would fail an audit (no encryption, wildcard IAM, no TLS).
  - `MEDIUM` — defense-in-depth hygiene (missing tags, no log retention configured).
  - `LOW` — code-quality smell (deprecated TF syntax).
