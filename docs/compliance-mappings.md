# Compliance mappings

Every check in cspm-scanner returns a `Frameworks()` slice — the controls that finding violates. This document is the full table, indexed two ways: **by check** and **by framework**.

## By check

| Check ID | SOC2 | NIST 800-53 | CIS AWS |
|---|---|---|---|
| `CSPM-AWS-S3-001`  — S3 missing SSE | CC6.7 | SC-28 | 2.1.1 |
| `CSPM-AWS-S3-002`  — S3 public ACL | CC6.1 | AC-3  | 2.1.5 |
| `CSPM-AWS-EC2-001` — SG admin port open | CC6.6 | AC-4  | 5.2 |
| `CSPM-AWS-RDS-001` — RDS publicly_accessible | CC6.6 | SC-7  | 2.3.3 |
| `CSPM-AWS-RDS-002` — RDS unencrypted | CC6.7 | SC-28 | 2.3.1 |
| `CSPM-AWS-IAM-001` — IAM wildcard | CC6.1 | AC-6  | 1.16 |

## By framework

### SOC2

| Control | Description | Checks |
|---|---|---|
| **CC6.1** — Logical and physical access controls | Restrict access to data based on least privilege | `S3-002`, `IAM-001` |
| **CC6.6** — Perimeter access controls | Restrict network and remote access | `EC2-001`, `RDS-001` |
| **CC6.7** — Restrict transmission and disposal of confidential data | Encrypt data at rest and in transit | `S3-001`, `RDS-002` |

### NIST 800-53 Rev 5

| Control | Description | Checks |
|---|---|---|
| **AC-3** — Access Enforcement | `S3-002` |
| **AC-4** — Information Flow Enforcement | `EC2-001` |
| **AC-6** — Least Privilege | `IAM-001` |
| **SC-7** — Boundary Protection | `RDS-001` |
| **SC-28** — Protection of Information at Rest | `S3-001`, `RDS-002` |

### CIS AWS Foundations Benchmark v3.0

| Control | Description | Checks |
|---|---|---|
| **1.16** — IAM policies should not allow full "*" admin privileges | `IAM-001` |
| **2.1.1** — S3 buckets should have server-side encryption enabled | `S3-001` |
| **2.1.5** — S3 buckets should block public access | `S3-002` |
| **2.3.1** — RDS instances should have storage encryption enabled | `RDS-002` |
| **2.3.3** — RDS instances should not be publicly accessible | `RDS-001` |
| **5.2** — Security groups should not allow ingress from 0.0.0.0/0 to admin ports | `EC2-001` |

## How to use these in an audit

Auditors typically want to see, for each control:

1. **Evidence the control is enforced** — a CI badge showing cspm-scanner ran against every change. Add `cspm.sarif` as a CI artifact; auditors can verify it was produced and that violations failed the build.
2. **Evidence of remediation** — closed GitHub issues / PRs referencing the check ID.
3. **Evidence of coverage** — `cspm list-checks` output, demonstrating which controls the tool covers.

The `Frameworks()` mapping in cspm-scanner is the **machine-readable evidence** layer. Your audit narrative is built on top.

## Caveats

- Mappings are **conservative best-effort**, not legal advice. A finding that maps to "SOC2 CC6.1" means the auditor will likely cite it; whether your specific control implementation passes is still a judgment call.
- NIST 800-53 has dozens of controls per family. We pick the most directly applicable one, not all of them.
- CIS benchmarks are versioned. We track v3.0 as of late 2025; check IDs may shift slightly with new releases.
- If you spot a mapping you disagree with, open an issue with the auditor reasoning — we'd rather discuss than be silently wrong.
