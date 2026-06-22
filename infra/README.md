# infra/ — Terraform templates for CloudSentinel

This directory contains two Terraform configurations that together demonstrate the full detection lifecycle of CloudSentinel's 16 AWS scanner checks.

**`vulnerable/`** — intentionally misconfigured S3, IAM, CloudTrail, and Security Group resources that trigger every one of CloudSentinel's checks. This configuration is meant for LocalStack or `terraform plan` only; **never apply it against a real AWS account**. It is the "red scan" input: when CloudSentinel scans these resources, it should exit with code 1.

**`remediated/`** — the correctly-configured mirror of `vulnerable/`, with public access disabled, encryption enabled, least-privilege IAM policies, and restricted security group rules. When CloudSentinel scans these resources it should exit with code 0 (no critical findings).

Both directories share the same resource names and structure so they can be compared side-by-side. Pass `var.endpoint_url` (e.g. `http://localhost:4566`) to target LocalStack instead of real AWS.
