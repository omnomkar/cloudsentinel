from typing import List
import json
from botocore.exceptions import ClientError
from scanner import Finding


def run_s3_checks(client, region: str, reference_time=None) -> List[Finding]:
    findings = []
    buckets = client.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]
        findings.extend(_check_public_access_block(client, name, region))
        findings.extend(_check_public_acl(client, name, region))
        findings.extend(_check_bucket_policy_public(client, name, region))
        findings.extend(_check_encryption_at_rest(client, name, region))

    return findings


def _check_public_access_block(client, bucket_name: str, region: str) -> List[Finding]:
    try:
        resp = client.get_public_access_block(Bucket=bucket_name)
        config = resp["PublicAccessBlockConfiguration"]
        all_blocked = all([
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False),
        ])
        status = "PASS" if all_blocked else "FAIL"
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            status = "FAIL"
            config = {}
        else:
            raise

    return [Finding(
        resource_id=f"arn:aws:s3:::{bucket_name}",
        resource_type="AWS::S3::Bucket",
        check_id="S3_PUBLIC_ACCESS_BLOCK",
        check_name="S3 bucket public access block not fully enabled",
        severity="high",
        status=status,
        region=region,
        cloud="aws",
        remediation="Enable all four S3 Block Public Access settings on the bucket.",
        details={"bucket": bucket_name, "config": config},
    )]


def _check_public_acl(client, bucket_name: str, region: str) -> List[Finding]:
    try:
        resp = client.get_bucket_acl(Bucket=bucket_name)
        grants = resp.get("Grants", [])
        public_grantees = {
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        }
        is_public = any(
            g.get("Grantee", {}).get("URI") in public_grantees for g in grants
        )
        status = "FAIL" if is_public else "PASS"
    except Exception:
        status = "PASS"

    return [Finding(
        resource_id=f"arn:aws:s3:::{bucket_name}",
        resource_type="AWS::S3::Bucket",
        check_id="S3_PUBLIC_ACL",
        check_name="S3 bucket ACL grants public access",
        severity="critical",
        status=status,
        region=region,
        cloud="aws",
        remediation="Remove public ACL grants from the S3 bucket.",
        details={"bucket": bucket_name},
    )]


def _is_wildcard_principal(principal) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS", "")
        if isinstance(aws, str):
            return aws == "*"
        if isinstance(aws, list):
            return "*" in aws
    return False


def _check_bucket_policy_public(client, bucket_name: str, region: str) -> List[Finding]:
    try:
        resp = client.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(resp["Policy"])
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        is_public = any(
            stmt.get("Effect") == "Allow"
            and not stmt.get("Condition")  # a Condition (e.g. aws:sourceVpc) restricts exposure
            and _is_wildcard_principal(stmt.get("Principal"))
            for stmt in statements
        )
        status = "FAIL" if is_public else "PASS"
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchBucketPolicy", "NoSuchBucket"):
            status = "PASS"
        else:
            status = "PASS"
    except Exception:
        status = "PASS"

    return [Finding(
        resource_id=f"arn:aws:s3:::{bucket_name}",
        resource_type="AWS::S3::Bucket",
        check_id="S3_BUCKET_POLICY_PUBLIC",
        check_name="S3 bucket policy allows public access",
        severity="critical",
        status=status,
        region=region,
        cloud="aws",
        remediation="Update the bucket policy to remove public access statements.",
        details={"bucket": bucket_name},
    )]


def _check_encryption_at_rest(client, bucket_name: str, region: str) -> List[Finding]:
    try:
        client.get_bucket_encryption(Bucket=bucket_name)
        status = "PASS"
    except ClientError as e:
        if e.response["Error"]["Code"] in (
            "ServerSideEncryptionConfigurationNotFoundError",
            "NoSuchServerSideEncryptionConfiguration",
        ):
            status = "FAIL"
        else:
            status = "FAIL"
    except Exception:
        status = "FAIL"

    return [Finding(
        resource_id=f"arn:aws:s3:::{bucket_name}",
        resource_type="AWS::S3::Bucket",
        check_id="S3_ENCRYPTION_AT_REST",
        check_name="S3 bucket does not have server-side encryption enabled",
        severity="medium",
        status=status,
        region=region,
        cloud="aws",
        remediation="Enable default server-side encryption (SSE-S3 or SSE-KMS) on the bucket.",
        details={"bucket": bucket_name},
    )]
