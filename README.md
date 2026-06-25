# CloudSentinel

CloudSentinel is a cloud security posture management (CSPM) scanner. It inspects
AWS and Azure resources for common misconfigurations, maps every finding to a
CIS Benchmark control ID, and produces JSON and Markdown reports you can read
locally or wire into CI as a pass/fail gate.

It's read-only: CloudSentinel never modifies the resources it scans.

## Features

**AWS checks** (mapped to the CIS Amazon Web Services Foundations Benchmark):
- **S3** — public access block, public ACLs, public bucket policies, encryption at rest
- **IAM** — wildcard-action policies, unused roles, root account MFA, access key age
- **CloudTrail** — trail existence, logging state, log file validation, trail bucket encryption
- **Security Groups** — SSH/RDP open to the world, unrestricted egress, overly permissive port ranges

**Azure checks** (mapped to the CIS Microsoft Azure Foundations Benchmark **v1.4.0**, released
11-26-2021 — control numbers shift between benchmark versions, so this version is pinned
explicitly in [`scanner/reporter.py`](scanner/reporter.py)):
- **Storage Accounts** — public blob access, secure transfer (HTTPS-only), customer-managed
  key encryption, default network access rule
- **Network Security Groups** — SSH/RDP open to the world, wide inbound port ranges,
  unrestricted egress

Checks without a clean matching control in the pinned benchmark version are left unmapped
("N/A" in reports) rather than assigned a plausible-looking but incorrect number.

Every finding carries a severity (`critical`, `high`, `medium`, `low`), and CloudSentinel can
gate a CI pipeline by exiting non-zero when findings at or above a chosen severity exist.

## Installation

### Docker

```bash
docker build -t cloudsentinel .
docker run --rm cloudsentinel --help
```

Credentials and configuration (AWS credentials/region, Azure auth, endpoint URLs) are never
baked into the image — pass them at `docker run` time via environment variables or CLI flags,
the same way you would when running `main.py` directly. For example, to scan against
LocalStack:

```bash
docker run --rm \
  -e AWS_ACCESS_KEY_ID=test \
  -e AWS_SECRET_ACCESS_KEY=test \
  -e AWS_DEFAULT_REGION=us-east-1 \
  --network host \
  cloudsentinel --cloud aws --endpoint-url http://localhost:4566
```

### Local (venv + pip)

```bash
python3 -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows
pip install -r requirements.txt
python main.py --help
```

## Usage

CLI flags (from `main.py`):

| Flag | Description |
|---|---|
| `--cloud {aws,azure,all}` | Which cloud(s) to scan. Default: `aws`. |
| `--region REGION` | AWS region to scan. Default: `us-east-1`. (Azure resources use their own location, not this flag.) |
| `--subscription-id ID` | Azure subscription ID. Required when `--cloud` is `azure` or `all`. |
| `--endpoint-url URL` | Custom AWS endpoint (e.g. LocalStack) instead of real AWS. |
| `--fail-on {critical,high,medium,low}` | Severity threshold that causes a non-zero exit. Default: `critical`. |
| `--output-dir DIR` | Where to write the JSON/Markdown reports. Default: `./reports`. |
| `--exclude-checks CHECK_IDS` | Comma-separated check IDs to exclude from findings and the fail-on gate. |

Examples:

```bash
# Scan AWS against real AWS credentials in the environment
python main.py --cloud aws --region us-east-1

# Scan AWS against LocalStack
python main.py --cloud aws --endpoint-url http://localhost:4566

# Scan Azure
python main.py --cloud azure --subscription-id <subscription-id>

# Scan both clouds, exclude two known-noisy checks, fail on high severity or above
python main.py --cloud all --subscription-id <subscription-id> \
  --exclude-checks CLOUDTRAIL_NO_TRAIL,IAM_ROOT_NO_MFA --fail-on high
```

Exit codes: `0` = no findings at/above the `--fail-on` threshold, `1` = gate failed,
`2` = scan error (e.g. missing `--subscription-id`, credential failure).

## Sample report output

A trimmed excerpt from a real run (`reports/cloudsentinel_report_*.md`):

```markdown
# CloudSentinel Report

Generated: 2026-06-22 21:13:22 UTC

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 0 |
| **Total** | **2** |

## Findings

### 🟡 Medium (2)

#### Security group allows unrestricted egress to 0.0.0.0/0
- **Check ID:** `SG_UNRESTRICTED_EGRESS`
- **CIS Control:** 5.4
- **Resource:** `sg-af979a8cb2c4fa640`
- **Region:** us-east-1
- **Remediation:** Restrict egress rules to specific destinations and ports.
```

The JSON report alongside it contains the same data (`summary` + full `findings` list) in
machine-readable form.

## Testing

```bash
pip install -r requirements.txt
pytest tests/ -v
```

82 tests cover every AWS check against [moto](https://github.com/getmoto/moto)-mocked AWS
services, and every Azure check against a mocked Azure SDK client (`unittest.mock`), each with
both a misconfigured and a compliant case.

## CI/CD

GitHub Actions runs on every push and pull request to `main`:
- **`.github/workflows/checkov.yml`** — static analysis of the Terraform in `infra/` with
  [Checkov](https://www.checkov.io/), verifying the vulnerable config is flagged and the
  remediated config is clean.
- **`.github/workflows/scan.yml`** — spins up LocalStack, applies the `infra/vulnerable` and
  `infra/remediated` Terraform configs in turn, and runs CloudSentinel against each, verifying
  the expected exit code (1 for vulnerable, 0 for remediated).

## Known limitations

See [`infra/README.md`](infra/README.md) for the documented LocalStack quirks that require
excluding `CLOUDTRAIL_NO_TRAIL` and `IAM_ROOT_NO_MFA` from the CI runtime scan (LocalStack's
free tier doesn't support trail creation or root MFA simulation) — this is a LocalStack
limitation, not a gap in scanner coverage; both checks are still exercised by the unit test
suite.

## License

MIT — see [`LICENSE`](LICENSE).
