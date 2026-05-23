# Contributing to cspm-scanner

PRs welcome. The goal is keeping the bar high: tight scope, audit-ready findings, single binary, fast.

## The development loop

```bash
git clone https://github.com/mohidev-tech/cspm-scanner
cd cspm-scanner
go mod tidy
go test -race ./...                 # green = ready
go run ./cmd/cspm scan testdata/bad # see real findings
```

## Adding a new check

This is the most common contribution. Five steps, ~10 minutes:

1. **Pick an ID.** Format: `CSPM-<CLOUD>-<SERVICE>-<NNN>` — e.g. `CSPM-AWS-LAMBDA-001`. Look at `cmd/cspm list-checks` to pick the next number.

2. **Create the check file** under `internal/checks/`. One file per resource family is the convention (e.g. all S3 checks live in `s3.go`). Implement the `scanner.Check` interface:

   ```go
   type LambdaPublicURL struct{}
   func (LambdaPublicURL) ID() string                          { return "CSPM-AWS-LAMBDA-001" }
   func (LambdaPublicURL) Title() string                       { return "Lambda function URL is public" }
   func (LambdaPublicURL) Severity() scanner.Severity          { return scanner.SeverityHigh }
   func (LambdaPublicURL) Description() string                 { return "..." }
   func (LambdaPublicURL) Remediation() string                 { return "..." }
   func (LambdaPublicURL) Frameworks() []scanner.FrameworkControl { return []... }
   func (c LambdaPublicURL) Evaluate(r scanner.Resource) *scanner.Finding {
     if r.Type != "aws_lambda_function_url" { return nil }
     if attr(r, "authorization_type") == `"NONE"` {
         return finding(c, r, `authorization_type = "NONE"`)
     }
     return nil
   }
   ```

3. **Register the check** in `internal/checks/registry.go` — append to the `All()` slice.

4. **Add fixtures** under `testdata/`:
   - `testdata/bad/` — Terraform that should fire this rule. Existing file is fine if you add a new resource.
   - `testdata/good/` — Terraform that should NOT fire it. Important: prevents false positives.

5. **Run the tests.** `go test ./...` exercises both fixtures plus the registry. If green, open a PR.

## Pull request checklist

- [ ] `go test -race ./...` passes.
- [ ] `go vet ./...` is clean.
- [ ] New check has both a bad and a good fixture.
- [ ] README's "What it catches" table is updated.
- [ ] If you changed CLI flags or output formats, the README's CI examples still work.

## Coding conventions

- **No new external dependencies** without a strong justification. We have one (hcl/v2). That's the bar.
- **Conservative on variable references.** If a check needs a literal value and gets `var.foo`, it should NOT fire. False positives are worse than false negatives here — they erode trust faster.
- **Severity discipline.** Use CRITICAL only for "literally a data breach pattern." HIGH for "would fail an audit." MEDIUM for hygiene.
- **One check, one file.** Don't bundle "S3 checks" into one struct. Many small files is the right shape.

## Documentation

The Frameworks() return value is the audit-mapping output. **Always include all three** (SOC2, NIST 800-53, CIS AWS) when applicable. A check that maps to only one framework is fine, but a check that maps to none of them is asking why it exists.

## Reporting security issues

Don't open a public issue for security problems. See [SECURITY.md](SECURITY.md).

## License of contributions

By submitting a PR, you agree your contribution is Apache 2.0 licensed (the same license as the project). See [LICENSE](LICENSE) and [NOTICE](NOTICE).
