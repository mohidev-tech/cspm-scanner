# Security policy

## Reporting a vulnerability

**Don't open a public issue.** Email the maintainer at the address on the [profile page](https://github.com/mohidev-tech), or use GitHub's private vulnerability reporting:

→ [Report a vulnerability](https://github.com/mohidev-tech/cspm-scanner/security/advisories/new)

Please include:

- A short description of the issue.
- The scanner version (`cspm version`) and Go version (`go version`).
- A minimal reproducer — ideally a `.tf` file or a CI command line.
- The impact you believe it has (e.g. "could be used to crash the scanner on adversarial input", "could miss a class of finding silently").

You'll get an acknowledgement within **72 hours**. Critical issues are addressed and disclosed within **30 days** of acknowledgement; lower-severity issues within 90 days. We'll credit you in the release notes unless you'd rather stay anonymous.

## What's in scope

- Parser crashes or hangs on adversarial HCL input.
- Findings silently dropped due to a parser bug (false negatives in the engine, not in individual checks).
- Privilege escalation or arbitrary file read via the `--output` flag or any future feature that touches the filesystem.

## What's out of scope

- **Individual checks missing a finding** in a specific configuration — that's a bug, please open a regular issue with a fixture under `testdata/`.
- **Variable / module-resolution gaps** — see [ADR 0001](docs/adr/0001-hcl-source-text-over-evaluated-plan.md); this is deliberate scope.
- Vulnerabilities in `hcl/v2` or the Go standard library — please report those upstream first, then let us know if we need to bump a dep.

## Supply chain

This repo's CI builds binaries via [go-releaser](https://goreleaser.com/) and signs them with `cosign` keyless (planned — see [secure-supply-chain](https://github.com/mohidev-tech/secure-supply-chain) for the pattern). When you install via `install.sh`, the script downloads from the GitHub Releases page. Verify the checksum if you're paranoid; we publish `cspm_<version>_checksums.txt` alongside every release.

## Hardening you can do

If you run `cspm` in a CI pipeline:

- Pin to a specific release tag — don't pull `@latest` in production CI.
- Run it with the smallest permissions that work; the scanner only needs read on the IaC directory + write on the `--output` path.
- Sandbox the runner if you scan untrusted Terraform (e.g. from contributors).
