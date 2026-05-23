# cspm-scanner 🛡️

A Go CLI that scans Terraform for cloud misconfigurations and maps every finding to **SOC2 / NIST 800-53 / CIS AWS**.

Zero credentials. Zero `terraform init`. Runs in 50ms on a real repo. SARIF output lands findings in the GitHub Security tab.

[![ci](https://github.com/mohidev-tech/cspm-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/mohidev-tech/cspm-scanner/actions/workflows/ci.yml)
[![license: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## What it catches

| Check | Severity | Detects |
|---|---|---|
| `CSPM-AWS-S3-001` | HIGH | S3 bucket without `server_side_encryption_configuration` |
| `CSPM-AWS-S3-002` | CRITICAL | S3 bucket ACL `public-read` or `public-read-write` |
| `CSPM-AWS-EC2-001` | CRITICAL | Security group with `0.0.0.0/0` ingress on SSH (22) or RDP (3389) |
| `CSPM-AWS-RDS-001` | HIGH | RDS instance with `publicly_accessible = true` |
| `CSPM-AWS-RDS-002` | HIGH | RDS instance with `storage_encrypted = false` (the default) |
| `CSPM-AWS-IAM-001` | HIGH | IAM policy document with `"Action": "*"` or `"Resource": "*"` on Allow |

Each finding maps to **SOC2 / NIST / CIS AWS** control IDs — that mapping is what makes the output usable for audit prep, not just a noisy "fix this" list.

## Quickstart

```bash
go install github.com/mohidev-tech/cspm-scanner/cmd/cspm@latest

# Console output
cspm scan ./infra/terraform

# SARIF for GitHub Code Scanning
cspm scan --format sarif --output cspm.sarif ./infra/terraform

# Fail the build only on CRITICAL
cspm scan --fail-on CRITICAL ./infra/terraform

# What does this scanner check?
cspm list-checks
```

## Example output

```
[CRITICAL] S3 bucket has a public ACL
  id:        CSPM-AWS-S3-002
  resource:  aws_s3_bucket.logs
  location:  testdata/bad/main.tf:3
  why:       Public S3 ACLs are the #1 cloud-misconfig data-breach pattern. ... — acl = public-read
  fix:       Set acl = "private" and pair with an "aws_s3_bucket_public_access_block" with all four flags = true.
  maps to:   SOC2 CC6.1, NIST 800-53 AC-3, CIS AWS 2.1.5
```

## In CI

```yaml
- name: cspm scan
  run: |
    go install github.com/mohidev-tech/cspm-scanner/cmd/cspm@latest
    cspm scan --format sarif --output cspm.sarif ./infra
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cspm.sarif
```

## Design

| Choice | Why |
|---|---|
| Scan source text, not the evaluated plan | No AWS creds in CI. PR feedback in seconds. See [ADR 0001](docs/adr/0001-hcl-source-text-over-evaluated-plan.md) |
| One check = one Go file | New rules are easy to write and easy to review. No DSL to learn |
| Compliance mapping baked in | Output is audit-ready, not just developer-ready |
| SARIF as a first-class output | The GitHub Security tab is where engineering already looks |

## How this slots into the portfolio

The flagship [devsecops-platform](https://github.com/mohidev-tech/devsecops-platform) ships its own Terraform under `infra/terraform/cloud/`. This scanner runs against it in a future PR — dogfooding the security tooling on the platform's own IaC. Combined with [secure-supply-chain](https://github.com/mohidev-tech/secure-supply-chain) (signed images + admission verification), the portfolio covers IaC → build → publish → admit.

## What's missing — deliberately

- **Plan-time scanning** — variables and locals are not resolved. See ADR 0001 for the trade-off. Pair with `terraform show -json | <other tool>` for the missing layer.
- **Cloud-account live scan** — this is a v2 feature. The architecture supports it (Resource is decoupled from parser); a `cspm aws` subcommand would call AWS APIs and produce the same Resource shape.

## License

Apache 2.0 — see [LICENSE](LICENSE).
