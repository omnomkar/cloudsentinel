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

### Medium (2)

#### Security group allows unrestricted egress to 0.0.0.0/0
- **Check ID:** `SG_UNRESTRICTED_EGRESS`
- **CIS Control:** 5.4
- **Resource:** `sg-4b454c530d4b90c6e`
- **Region:** us-east-1
- **Remediation:** Restrict egress rules to specific destinations and ports.

#### Security group allows unrestricted egress to 0.0.0.0/0
- **Check ID:** `SG_UNRESTRICTED_EGRESS`
- **CIS Control:** 5.4
- **Resource:** `sg-dd302009469c0651d`
- **Region:** us-east-1
- **Remediation:** Restrict egress rules to specific destinations and ports.
