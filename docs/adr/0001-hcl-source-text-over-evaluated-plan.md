# ADR 0001 — Scan HCL source text, not the evaluated plan

## Status
Accepted

## Context
A Terraform misconfig scanner has two possible inputs:

1. **The source text** (`*.tf` files parsed via `hcl/v2`). Pros: fast, no AWS creds, no `terraform init`. Cons: cannot resolve variables, locals, or data sources.
2. **The evaluated plan** (`terraform show -json plan.bin`). Pros: every value is materialized. Cons: requires credentials, network, working providers, and a successful plan to even start.

## Decision
Scan the HCL source text. Variable references are reported as their *literal* form (`var.bucket_name`, `"${var.encrypted}"`). Checks that depend on a literal value are conservative: when the value is a reference, the check does not fire.

## Why
- **CI runs without credentials.** A platform-engineering scanner that requires production AWS credentials in CI is a worse risk than what it catches.
- **PRs get feedback in seconds, not minutes.** No plan, no Terraform init, no provider downloads.
- **Misconfigurations are usually visible in the source.** `acl = "public-read"`, `publicly_accessible = true`, and `cidr_blocks = ["0.0.0.0/0"]` are all literal. The cases where a misconfig hides behind a variable are real but uncommon, and they get caught by `tfsec`/`checkov`-style plan-time scanning in a separate pipeline.

## Trade-off captured explicitly
We will miss findings of the form `publicly_accessible = var.expose_db` where the variable defaults to true. This is a *deliberate false-negative*. The right way to mitigate it is to require literal booleans for security-relevant flags via a linter, not to introduce a credentialed scan.

## Consequences
- ✅ Zero-credential install: `go install ./cmd/cspm` is enough.
- ✅ Works on any IaC repo regardless of cloud account state.
- ⚠️ Some findings need plan-time scanning to catch. Document this in the README and recommend pairing with `terraform show -json | trivy` for the missing layer.
