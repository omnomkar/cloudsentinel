# infra/ — Terraform templates for CloudSentinel

This directory contains two Terraform configurations that together demonstrate the full detection lifecycle of CloudSentinel's 16 AWS scanner checks.

**`vulnerable/`** — intentionally misconfigured S3, IAM, CloudTrail, and Security Group resources that trigger every one of CloudSentinel's checks. This configuration is meant for LocalStack or `terraform plan` only; **never apply it against a real AWS account**. It is the "red scan" input: when CloudSentinel scans these resources, it should exit with code 1.

**`remediated/`** — the correctly-configured mirror of `vulnerable/`, with public access disabled, encryption enabled, least-privilege IAM policies, and restricted security group rules. When CloudSentinel scans these resources it should exit with code 0 (no critical findings).

Both directories share the same resource names and structure so they can be compared side-by-side. Pass `var.endpoint_url` (e.g. `http://localhost:4566`) to target LocalStack instead of real AWS.

## CI runtime scan — LocalStack check exclusions

The GitHub Actions runtime scan (`.github/workflows/scan.yml`) passes `--exclude-checks CLOUDTRAIL_NO_TRAIL,IAM_ROOT_NO_MFA` to both the vulnerable and remediated scanner invocations. This is applied to both cycles so the exclusions are visibly tied to the LocalStack environment rather than appearing to force a clean result.

**`CLOUDTRAIL_NO_TRAIL`:** LocalStack's free tier returns HTTP 501 for the CloudTrail `CreateTrail` API call. The `aws_cloudtrail` resource in both Terraform configs uses `count = var.enable_cloudtrail_resource ? 1 : 0` with `enable_cloudtrail_resource=false` in CI, so no trail is ever deployed. With no trail present, CloudSentinel emits a critical `CLOUDTRAIL_NO_TRAIL` finding, which would cause both scans to exit 1.

**`IAM_ROOT_NO_MFA`:** LocalStack's root account simulation does not model MFA state at all, so this check always fires regardless of actual configuration. It is not a real misconfiguration in the LocalStack environment.

**Coverage is not lost:** both excluded checks are exercised by:
- Unit tests in `tests/` via moto mocks (Session 1), which run unconditionally in CI and test against real AWS IAM semantics.
- Checkov static analysis of the Terraform files (`.github/workflows/checkov.yml`), which runs regardless of this runtime exclusion.
