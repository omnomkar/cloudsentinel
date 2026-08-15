# CloudSentinel Report

Generated: 2026-08-15 11:32:17 UTC

## Summary

| Severity | Count |
|----------|-------|
| Critical | 6 |
| High | 3 |
| Medium | 5 |
| Low | 0 |
| **Total** | **14** |

## CIS Benchmark Mapping

| Check ID | CIS Control |
|----------|-------------|
| S3_PUBLIC_ACCESS_BLOCK | 2.1.5 |
| S3_PUBLIC_ACL | 2.1.5 |
| S3_BUCKET_POLICY_PUBLIC | 2.1.5 |
| S3_ENCRYPTION_AT_REST | 2.1.1 |
| IAM_WILDCARD_ACTION_POLICY | 1.16 |
| IAM_UNUSED_ROLE | 1.16 |
| IAM_ROOT_NO_MFA | 1.5 |
| IAM_ACCESS_KEY_AGE | 1.14 |
| CLOUDTRAIL_NO_TRAIL | 3.1 |
| CLOUDTRAIL_LOGGING_DISABLED | 3.1 |
| CLOUDTRAIL_LOG_VALIDATION_OFF | 3.2 |
| CLOUDTRAIL_S3_BUCKET_NO_ENCRYPT | 3.6 |
| SG_SSH_OPEN_TO_WORLD | 5.2 |
| SG_RDP_OPEN_TO_WORLD | 5.3 |
| SG_UNRESTRICTED_EGRESS | 5.4 |
| SG_OVERLY_PERMISSIVE | 5.4 |
| AZURE_STORAGE_SECURE_TRANSFER | 3.1 |
| AZURE_STORAGE_PUBLIC_BLOB_ACCESS | 3.5 |
| AZURE_STORAGE_NETWORK_ACCESS_ALL | 3.6 |
| AZURE_STORAGE_CMK_ENCRYPTION | 3.9 |
| AZURE_NSG_RDP_OPEN_TO_WORLD | 6.1 |
| AZURE_NSG_SSH_OPEN_TO_WORLD | 6.2 |

## Findings

### Critical (6)

#### S3 bucket ACL grants public access
- **Check ID:** `S3_PUBLIC_ACL`
- **CIS Control:** 2.1.5
- **Resource:** `arn:aws:s3:::cloudsentinel-vulnerable-data`
- **Region:** us-east-1
- **Remediation:** Remove public ACL grants from the S3 bucket.

#### S3 bucket policy allows public access
- **Check ID:** `S3_BUCKET_POLICY_PUBLIC`
- **CIS Control:** 2.1.5
- **Resource:** `arn:aws:s3:::cloudsentinel-vulnerable-data`
- **Region:** us-east-1
- **Remediation:** Update the bucket policy to remove public access statements.

#### Security group allows RDP (port 3389) from 0.0.0.0/0
- **Check ID:** `SG_RDP_OPEN_TO_WORLD`
- **CIS Control:** 5.3
- **Resource:** `sg-7f0c4b15c5bddafb9`
- **Region:** us-east-1
- **Remediation:** Restrict RDP access to known IP ranges instead of 0.0.0.0/0.

#### Security group allows SSH (port 22) from 0.0.0.0/0
- **Check ID:** `SG_SSH_OPEN_TO_WORLD`
- **CIS Control:** 5.2
- **Resource:** `sg-8453b70dfc013e877`
- **Region:** us-east-1
- **Remediation:** Restrict SSH access to known IP ranges instead of 0.0.0.0/0.

#### Security group allows RDP (port 3389) from 0.0.0.0/0
- **Check ID:** `SG_RDP_OPEN_TO_WORLD`
- **CIS Control:** 5.3
- **Resource:** `sg-8453b70dfc013e877`
- **Region:** us-east-1
- **Remediation:** Restrict RDP access to known IP ranges instead of 0.0.0.0/0.

#### Security group allows SSH (port 22) from 0.0.0.0/0
- **Check ID:** `SG_SSH_OPEN_TO_WORLD`
- **CIS Control:** 5.2
- **Resource:** `sg-359143e37f737968b`
- **Region:** us-east-1
- **Remediation:** Restrict SSH access to known IP ranges instead of 0.0.0.0/0.

### High (3)

#### S3 bucket public access block not fully enabled
- **Check ID:** `S3_PUBLIC_ACCESS_BLOCK`
- **CIS Control:** 2.1.5
- **Resource:** `arn:aws:s3:::cloudsentinel-vulnerable-data`
- **Region:** us-east-1
- **Remediation:** Enable all four S3 Block Public Access settings on the bucket.

#### IAM policy allows wildcard (*) actions
- **Check ID:** `IAM_WILDCARD_ACTION_POLICY`
- **CIS Control:** 1.16
- **Resource:** `arn:aws:iam::000000000000:policy/cloudsentinel-wildcard-admin`
- **Region:** us-east-1
- **Remediation:** Replace wildcard actions with specific, least-privilege permissions.

#### Security group allows a port range wider than 1024 ports from 0.0.0.0/0
- **Check ID:** `SG_OVERLY_PERMISSIVE`
- **CIS Control:** 5.4
- **Resource:** `sg-8453b70dfc013e877`
- **Region:** us-east-1
- **Remediation:** Narrow the port range in security group inbound rules to only required ports.

### Medium (5)

#### Security group allows unrestricted egress to 0.0.0.0/0
- **Check ID:** `SG_UNRESTRICTED_EGRESS`
- **CIS Control:** 5.4
- **Resource:** `sg-4b454c530d4b90c6e`
- **Region:** us-east-1
- **Remediation:** Restrict egress rules to specific destinations and ports.

#### Security group allows unrestricted egress to 0.0.0.0/0
- **Check ID:** `SG_UNRESTRICTED_EGRESS`
- **CIS Control:** 5.4
- **Resource:** `sg-4acb42711fb6dc638`
- **Region:** us-east-1
- **Remediation:** Restrict egress rules to specific destinations and ports.

#### Security group allows unrestricted egress to 0.0.0.0/0
- **Check ID:** `SG_UNRESTRICTED_EGRESS`
- **CIS Control:** 5.4
- **Resource:** `sg-7f0c4b15c5bddafb9`
- **Region:** us-east-1
- **Remediation:** Restrict egress rules to specific destinations and ports.

#### Security group allows unrestricted egress to 0.0.0.0/0
- **Check ID:** `SG_UNRESTRICTED_EGRESS`
- **CIS Control:** 5.4
- **Resource:** `sg-8453b70dfc013e877`
- **Region:** us-east-1
- **Remediation:** Restrict egress rules to specific destinations and ports.

#### Security group allows unrestricted egress to 0.0.0.0/0
- **Check ID:** `SG_UNRESTRICTED_EGRESS`
- **CIS Control:** 5.4
- **Resource:** `sg-359143e37f737968b`
- **Region:** us-east-1
- **Remediation:** Restrict egress rules to specific destinations and ports.
