# CloudSentinel

[![Runtime Scan](https://img.shields.io/github/actions/workflow/status/omnomkar/cloudsentinel/scan.yml?branch=main&label=Runtime%20Scan)](https://github.com/omnomkar/cloudsentinel/actions/workflows/scan.yml) [![Checkov](https://img.shields.io/github/actions/workflow/status/omnomkar/cloudsentinel/checkov.yml?branch=main&label=Checkov)](https://github.com/omnomkar/cloudsentinel/actions/workflows/checkov.yml) [![Python](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/) [![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

CloudSentinel is a cloud security posture management (CSPM) scanner. It inspects
AWS and Azure resources for common misconfigurations, maps every finding to a
CIS Benchmark control ID, and produces JSON and Markdown reports you can read
locally or wire into CI as a pass/fail gate.

It's read-only: CloudSentinel never modifies the resources it scans.

![CloudSentinel scanning a vulnerable and a remediated Terraform stack](demo/cloudsentinel.gif)

The same scanner, run against two Terraform stacks. Against `infra/vulnerable` it reports 6
critical findings and exits 1 (`GATE FAILED`); against `infra/remediated` it reports no
critical findings and exits 0 (`Gate passed`). Nothing about the scanner changes between the
two runs — only the infrastructure it is pointed at.

## How it works

```mermaid
flowchart TD
    subgraph AWSSCAN["AWS scanners"]
        S3["S3"]
        IAM["IAM"]
        CT["CloudTrail"]
        SG["Security Groups"]
    end

    subgraph AZSCAN["Azure scanners"]
        ST["Storage Accounts"]
        NSG["Network Security Groups"]
    end

    AGG["Aggregator<br/>dedup + severity ordering"]
    REP["Reporter<br/>JSON + Markdown + console"]
    GATE{"CI gate<br/>--fail-on threshold"}
    PASS["exit 0"]
    FAIL["exit 1"]

    S3 --> AGG
    IAM --> AGG
    CT --> AGG
    SG --> AGG
    ST --> AGG
    NSG --> AGG

    AGG --> REP
    REP --> GATE
    GATE -->|"nothing at or above threshold"| PASS
    GATE -->|"findings at or above threshold"| FAIL
```

Each scanner returns findings independently. The aggregator deduplicates them by
(resource, check) and orders them by severity; the reporter renders the same finding set three
ways (JSON, Markdown, console); the gate compares the highest severity present against
`--fail-on` and chooses the exit code.

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
| `--db-url URL` | PostgreSQL URL to persist results to (falls back to `DATABASE_URL`). Off when neither is set. See [Persistence & Drift Detection](#persistence--drift-detection). |
| `--diff` | Print drift versus the previous stored scan. Requires a database. |

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

## Persistence & Drift Detection

Persistence is opt-in. When `--db-url` or `DATABASE_URL` is set, each scan is written to
PostgreSQL ([`scanner/db.py`](scanner/db.py): psycopg v3, hand-written parameterized SQL, no
ORM). When neither is set, CloudSentinel makes no database connection, which is the default.

What gets stored:

- Each provider in a run gets its own `scans` row, so `--cloud all` writes two rows.
- The AWS account ID comes from `sts:GetCallerIdentity`. The Azure account ID is
  `--subscription-id`, which is required whenever Azure results are persisted.
- Only FAIL findings are stored, after `--exclude-checks` is applied.
- A connection failure reports only the host and database name. The URL, and any password
  in it, is never printed.

### Schema

[`migrations/001_init.sql`](migrations/001_init.sql):

```sql
CREATE TABLE scans (
    id          BIGSERIAL   PRIMARY KEY,
    provider    TEXT        NOT NULL CHECK (provider IN ('aws', 'azure')),
    account_id  TEXT        NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE findings (
    id             BIGSERIAL PRIMARY KEY,
    scan_id        BIGINT    NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    check_id       TEXT      NOT NULL,
    check_name     TEXT      NOT NULL,
    cis_control    TEXT,              -- NULL for checks with no CIS mapping
    severity       TEXT      NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    resource_id    TEXT      NOT NULL,
    resource_type  TEXT      NOT NULL,
    region         TEXT      NOT NULL,
    details        JSONB     NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (scan_id, check_id, resource_id)
);

CREATE INDEX findings_check_resource_idx ON findings (check_id, resource_id);
CREATE INDEX findings_severity_idx       ON findings (severity);
CREATE INDEX scans_provider_account_idx  ON scans (provider, account_id, started_at DESC);
```

The `(check_id, resource_id)` index exists so you can look up one finding's history across
every scan (for example, "since when has this security group had SSH open?"). The UNIQUE
index can't serve that query because its first column is `scan_id`.

### Drift (`--diff`)

`--diff` compares the scan that just ran with the previous scan for the same provider and
account. It finds NEW and RESOLVED findings with SQL `EXCEPT` and STILL OPEN findings with
`INTERSECT`. Findings are matched on `(check_id, resource_id)`, so a severity change on the
same resource counts as STILL OPEN, shown at its current severity. `--exclude-checks` findings
are never stored, so changing that list between runs shows up as drift.

```text
Drift — cloud: aws | account: 123456789012 | scan #5 vs #4
  NEW            2
  RESOLVED       1
  STILL OPEN     2

NEW (2):
  HIGH      S3_PUBLIC_ACCESS_BLOCK              2.1.5   arn:aws:s3:::drift-demo-bucket
  MEDIUM    S3_ENCRYPTION_AT_REST               2.1.1   arn:aws:s3:::drift-demo-bucket

RESOLVED (1):
  MEDIUM    SG_UNRESTRICTED_EGRESS              5.4     sg-d33c2dc18d190e7dc

STILL OPEN (2):
  CRITICAL  CLOUDTRAIL_NO_TRAIL                 3.1     aws:cloudtrail:us-east-1:no-trail
  CRITICAL  IAM_ROOT_NO_MFA                     1.5     arn:aws:iam::root
```

On the first stored scan for a provider and account, `--diff` prints `No previous scan to
compare` and doesn't report every finding as NEW. `--diff` never changes the exit code, which
still comes only from `--fail-on`.

### Running with Docker Compose

```bash
cp .env.example .env        # set POSTGRES_PASSWORD; .env is gitignored
docker compose up --build   # postgres:16 + the scanner (runs --cloud aws --diff)
```

The compose file has no hardcoded password: `POSTGRES_PASSWORD` must be set. The scanner
receives it as `PGPASSWORD` so it never appears in `DATABASE_URL`. The scanner container
starts only once Postgres passes its healthcheck.

The migration runs automatically because `./migrations` is mounted into
`/docker-entrypoint-initdb.d`. **That hook runs only when the data volume is empty.** For
future migrations on an existing volume, either apply them by hand
(`docker compose exec -T postgres psql -U cloudsentinel -d cloudsentinel < migrations/002_x.sql`)
or reset the volume with `docker compose down -v`, which deletes all stored scans.

## Sample report output

Both reports from the run shown in the GIF above are committed, so you can read the real
output rather than an excerpt of it:

- [`demo/sample-report-vulnerable.md`](demo/sample-report-vulnerable.md) — the `infra/vulnerable`
  stack: 14 findings (6 critical, 3 high, 5 medium), gate failed, exit 1.
- [`demo/sample-report-remediated.md`](demo/sample-report-remediated.md) — the `infra/remediated`
  stack: 2 findings (2 medium), gate passed, exit 0.

A trimmed excerpt from the remediated report:

```markdown
# CloudSentinel Report

Generated: 2026-08-15 11:34:03 UTC

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 0 |
| **Total** | **2** |

## Findings

### Medium (2)

#### Security group allows unrestricted egress to 0.0.0.0/0
- **Check ID:** `SG_UNRESTRICTED_EGRESS`
- **CIS Control:** 5.4
- **Resource:** `sg-4b454c530d4b90c6e`
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

`tests/test_db.py` adds persistence and drift tests. The ones that need a database run only
when `TEST_DATABASE_URL` points at a PostgreSQL server; otherwise they are skipped. Each test
uses its own throwaway schema:

```bash
docker run -d --rm -p 55432:5432 -e POSTGRES_PASSWORD=localtest postgres:16
TEST_DATABASE_URL=postgresql://postgres:localtest@localhost:55432/postgres pytest tests/ -v
```

## CI/CD

GitHub Actions runs on every push and pull request to `main`:
- **`.github/workflows/checkov.yml`** — static analysis of the Terraform in `infra/` with
  [Checkov](https://www.checkov.io/), verifying the vulnerable config is flagged and the
  remediated config is clean.
- **`.github/workflows/scan.yml` (`tests` job)** — runs the full pytest suite against a
  `postgres:16` service container, including the PostgreSQL-backed tests.
- **`.github/workflows/scan.yml`** — spins up LocalStack, applies the `infra/vulnerable` and
  `infra/remediated` Terraform configs in turn, and runs CloudSentinel against each, verifying
  the expected exit code (1 for vulnerable, 0 for remediated).

![GitHub Actions run of the Runtime Scan workflow](demo/actions-runtime-scan.png)

The workflow asserts its own expected exit codes rather than just running the scanner: it
requires exit 1 on the vulnerable stack and exit 0 on the remediated one, so a regression in
either direction fails CI — both the failing path and the passing path are tested. The
findings counts produced in CI match the local run shown in the GIF exactly: 14 total, 6
critical, 3 high, 5 medium.

## Known limitations

See [`infra/README.md`](infra/README.md) for the documented LocalStack quirks that require
excluding `CLOUDTRAIL_NO_TRAIL` and `IAM_ROOT_NO_MFA` from the CI runtime scan (LocalStack's
free tier doesn't support trail creation or root MFA simulation) — this is a LocalStack
limitation, not a gap in scanner coverage; both checks are still exercised by the unit test
suite.

## License

MIT — see [`LICENSE`](LICENSE).
