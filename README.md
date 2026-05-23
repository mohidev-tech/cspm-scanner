# 🛡️ cspm-scanner

> **Terraform misconfig scanner with built-in SOC2 / NIST / CIS mapping. Zero credentials. SARIF for the GitHub Security tab.**
> A free, source-text-only alternative to checkov / tfsec / snyk-iac for teams that want IaC compliance without the enterprise bill.

[![ci](https://github.com/mohidev-tech/cspm-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/mohidev-tech/cspm-scanner/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go 1.22+](https://img.shields.io/badge/go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![SOC2](https://img.shields.io/badge/SOC2-mapped-2E7D32)](docs/compliance-mappings.md)
[![NIST 800-53](https://img.shields.io/badge/NIST%20800--53-mapped-2E7D32)](docs/compliance-mappings.md)
[![CIS AWS](https://img.shields.io/badge/CIS%20AWS-mapped-2E7D32)](docs/compliance-mappings.md)

---

## What it does (real terminal output)

```
$ cspm scan testdata/bad

[CRITICAL] S3 bucket has a public ACL
  id:        CSPM-AWS-S3-002
  resource:  aws_s3_bucket.logs
  location:  testdata/bad/main.tf:3
  why:       Public S3 ACLs are the #1 cloud-misconfig data-breach pattern — acl = public-read
  fix:       Set acl = "private" and pair with an "aws_s3_bucket_public_access_block".
  maps to:   SOC2 CC6.1, NIST 800-53 AC-3, CIS AWS 2.1.5

[CRITICAL] Security group exposes admin port to the internet
  id:        CSPM-AWS-EC2-001
  resource:  aws_security_group.open
  location:  testdata/bad/main.tf:9
  why:       Security groups allowing 0.0.0.0/0 on SSH (22) or RDP (3389)...
             — ingress opens admin port to 0.0.0.0/0 (from=22 to=22)
  fix:       Restrict ingress to a VPN/bastion CIDR or use Systems Manager Session Manager.
  maps to:   SOC2 CC6.6, NIST 800-53 AC-4, CIS AWS 5.2

[HIGH] RDS instance is publicly accessible
  id:        CSPM-AWS-RDS-001
  resource:  aws_db_instance.db
  ...

summary: 6 findings  (CRITICAL=2  HIGH=4  MEDIUM=0  LOW=0)
```

Exit code is `1` — `--fail-on` defaults to `HIGH`. Drop it into CI as-is.

---

## Why you want this

| | **cspm-scanner** | checkov | tfsec | Snyk IaC |
|---|---|---|---|---|
| **Price** | Free (Apache 2.0) | Free | Free (archived 2023) | Free tier — 100 scans/mo |
| **Credentials required** | ❌ None | ❌ None | ❌ None | ✅ Snyk account |
| **Compliance mapping in output** | ✅ SOC2 + NIST + CIS per finding | ⚠️ Tags only | ⚠️ Tags only | ✅ |
| **SARIF first-class** | ✅ `--format sarif` | ✅ | ✅ | ✅ |
| **External runtime deps** | hcl/v2 only | python + many | go + many | proprietary |
| **Binary size** | ~6 MB single binary | ~120 MB python+deps | ~30 MB | n/a (SaaS) |
| **Cold-start time** | <50 ms | ~3 s | ~500 ms | network |
| **Add a new rule** | One Go file, ~40 lines | Python class hierarchy | Go + interfaces | n/a |
| **License** | Apache 2.0 | Apache 2.0 | MIT | proprietary |

This is not a checkov clone. It's **the smallest scanner that maps every finding to an auditor-friendly control ID**, ships SARIF as a first-class output, and has zero non-Go dependencies. Drop the binary into any CI runner and it just runs.

---

## Quickstart

### Option 1 — one-line install

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/mohidev-tech/cspm-scanner/main/install.sh | sh

# Windows (PowerShell)
iwr -useb https://raw.githubusercontent.com/mohidev-tech/cspm-scanner/main/install.ps1 | iex
```

### Option 2 — go install

```bash
go install github.com/mohidev-tech/cspm-scanner/cmd/cspm@latest
```

### Run it

```bash
cspm scan ./infra/terraform              # default: console + fail on HIGH
cspm scan --format json   ./infra        # machine-readable
cspm scan --format sarif  ./infra > cspm.sarif
cspm scan --fail-on CRITICAL ./infra     # gentler gate
cspm list-checks                         # what's in the catalog?
```

---

## What it catches

| Check ID | Severity | Detects | Maps to |
|---|---|---|---|
| `CSPM-AWS-S3-001` | HIGH | S3 bucket without `server_side_encryption_configuration` | SOC2 CC6.7 · NIST SC-28 · CIS AWS 2.1.1 |
| `CSPM-AWS-S3-002` | CRITICAL | S3 bucket ACL `public-read` / `public-read-write` | SOC2 CC6.1 · NIST AC-3 · CIS AWS 2.1.5 |
| `CSPM-AWS-EC2-001` | CRITICAL | Security group with `0.0.0.0/0` ingress on SSH/RDP | SOC2 CC6.6 · NIST AC-4 · CIS AWS 5.2 |
| `CSPM-AWS-RDS-001` | HIGH | RDS instance `publicly_accessible = true` | SOC2 CC6.6 · NIST SC-7 · CIS AWS 2.3.3 |
| `CSPM-AWS-RDS-002` | HIGH | RDS instance `storage_encrypted = false` (the default!) | SOC2 CC6.7 · NIST SC-28 · CIS AWS 2.3.1 |
| `CSPM-AWS-IAM-001` | HIGH | IAM policy with `"Action": "*"` or `"Resource": "*"` on Allow | SOC2 CC6.1 · NIST AC-6 · CIS AWS 1.16 |

Roadmap: GCP, Azure, Kubernetes manifests, drift detection against live cloud state. Each is a separate satellite project.

---

## Use it in CI

### GitHub Actions — fail on HIGH, upload to Security tab

```yaml
- name: cspm scan
  run: |
    curl -fsSL https://raw.githubusercontent.com/mohidev-tech/cspm-scanner/main/install.sh | sh
    cspm scan --format sarif --output cspm.sarif --fail-on HIGH ./infra
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: cspm.sarif
    category: cspm
```

### GitLab CI

```yaml
cspm:
  image: golang:1.22-alpine
  script:
    - go install github.com/mohidev-tech/cspm-scanner/cmd/cspm@latest
    - cspm scan --format json --output cspm.json --fail-on HIGH infra/
  artifacts:
    paths: [cspm.json]
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: cspm
      name: cspm-scanner
      entry: cspm scan --fail-on CRITICAL
      language: system
      pass_filenames: false
      files: \.tf$
```

---

## Design choices

| Choice | Why |
|---|---|
| Scan **source text** via `hcl/v2`, not `terraform show -json` | Zero credentials in CI. PR feedback in <1s. Works on any IaC repo regardless of cloud-account state. [ADR 0001](docs/adr/0001-hcl-source-text-over-evaluated-plan.md) |
| **One check = one Go file** | New rules are a 40-line PR; reviewing one is reading one file |
| **Compliance mapping in the `Check` interface itself** | Output is audit-ready, not just developer-ready — every finding lists the SOC2/NIST/CIS control it violates |
| **SARIF as a first-class output** | The GitHub Security tab is where engineering already looks. Not a separate dashboard |
| **Stdlib `flag`, no cobra** | One external dep (hcl/v2). Single ~6 MB binary |

---

## Limitations — documented, not hidden

We **deliberately** don't scan the evaluated Terraform plan. That means:

- `publicly_accessible = var.expose_db` is **not detected** (we don't resolve `var.expose_db`).
- Module outputs flowing into resources are **not detected**.
- Live AWS account state drift is **not detected** — this is a static scanner, not CSPM-as-a-Service.

If you need those, pair us with `terraform show -json | trivy iac` (catches variable resolution) and a runtime CSPM (Prowler, Cloud Custodian) for live-account drift. [ADR 0001](docs/adr/0001-hcl-source-text-over-evaluated-plan.md) captures the trade-off.

---

## How this slots into the portfolio

| Repo | What it does | Connection |
|---|---|---|
| **[devsecops-platform](https://github.com/mohidev-tech/devsecops-platform)** | The cluster + the secured app | Has its own Terraform — scanned by cspm-scanner |
| **[secure-supply-chain](https://github.com/mohidev-tech/secure-supply-chain)** | Cosign-signed images + admission verification | Builds the images the platform admits |
| **cspm-scanner** *(this repo)* | Validates the IaC the platform is built from | Closes the loop: IaC → build → publish → admit |

---

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue privately, see [SECURITY.md](SECURITY.md).

## License

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
