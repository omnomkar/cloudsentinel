from typing import List, Optional
import boto3
from botocore.exceptions import ClientError
from scanner import Finding


def run_cloudtrail_checks(client, region: str, reference_time=None, s3_client=None) -> List[Finding]:
    if s3_client is None:
        s3_client = boto3.client("s3", region_name=region)

    findings = []

    try:
        trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
    except Exception:
        trails = []

    if not trails:
        findings.append(Finding(
            resource_id=f"aws:cloudtrail:{region}:no-trail",
            resource_type="AWS::CloudTrail::Trail",
            check_id="CLOUDTRAIL_NO_TRAIL",
            check_name="No CloudTrail trail exists in region",
            severity="critical",
            status="FAIL",
            region=region,
            cloud="aws",
            remediation="Create a CloudTrail trail to enable API activity logging.",
            details={"region": region},
        ))
        return findings

    findings.append(Finding(
        resource_id=f"aws:cloudtrail:{region}:trail-exists",
        resource_type="AWS::CloudTrail::Trail",
        check_id="CLOUDTRAIL_NO_TRAIL",
        check_name="No CloudTrail trail exists in region",
        severity="critical",
        status="PASS",
        region=region,
        cloud="aws",
        remediation="Create a CloudTrail trail to enable API activity logging.",
        details={"region": region},
    ))

    for trail in trails:
        trail_name = trail.get("Name", "unknown")
        trail_arn = trail.get("TrailARN", f"arn:aws:cloudtrail:{region}:unknown:{trail_name}")

        findings.extend(_check_logging_disabled(client, trail_name, trail_arn, region))
        findings.extend(_check_log_validation(trail, trail_arn, region))
        findings.extend(_check_s3_bucket_encryption(trail, trail_arn, region, s3_client))

    return findings


def _check_logging_disabled(client, trail_name: str, trail_arn: str, region: str) -> List[Finding]:
    try:
        status_resp = client.get_trail_status(Name=trail_name)
        is_logging = status_resp.get("IsLogging", False)
        status = "PASS" if is_logging else "FAIL"
    except Exception:
        status = "FAIL"

    return [Finding(
        resource_id=trail_arn,
        resource_type="AWS::CloudTrail::Trail",
        check_id="CLOUDTRAIL_LOGGING_DISABLED",
        check_name="CloudTrail trail logging is disabled",
        severity="critical",
        status=status,
        region=region,
        cloud="aws",
        remediation="Enable logging on the CloudTrail trail.",
        details={"trail_name": trail_name},
    )]


def _check_log_validation(trail: dict, trail_arn: str, region: str) -> List[Finding]:
    validation_enabled = trail.get("LogFileValidationEnabled", False)
    status = "PASS" if validation_enabled else "FAIL"

    return [Finding(
        resource_id=trail_arn,
        resource_type="AWS::CloudTrail::Trail",
        check_id="CLOUDTRAIL_LOG_VALIDATION_OFF",
        check_name="CloudTrail log file validation is disabled",
        severity="medium",
        status=status,
        region=region,
        cloud="aws",
        remediation="Enable log file validation on the CloudTrail trail.",
        details={"trail_name": trail.get("Name")},
    )]


def _check_s3_bucket_encryption(trail: dict, trail_arn: str, region: str, s3_client=None) -> List[Finding]:
    # AWS API uses KMSKeyId; moto uses KmsKeyId — check both
    kms_key = trail.get("KMSKeyId") or trail.get("KmsKeyId")
    if kms_key:
        status = "PASS"
    else:
        # Fall back to checking the trail's S3 bucket for any SSE (AES256 or KMS)
        bucket_name = trail.get("S3BucketName")
        if bucket_name and s3_client:
            try:
                s3_client.get_bucket_encryption(Bucket=bucket_name)
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
        else:
            status = "FAIL"

    return [Finding(
        resource_id=trail_arn,
        resource_type="AWS::CloudTrail::Trail",
        check_id="CLOUDTRAIL_S3_BUCKET_NO_ENCRYPT",
        check_name="CloudTrail S3 bucket has no encryption at rest configured",
        severity="medium",
        status=status,
        region=region,
        cloud="aws",
        remediation="Enable SSE-S3 or SSE-KMS encryption on the CloudTrail S3 bucket, or configure a KMS key on the trail itself.",
        details={"trail_name": trail.get("Name"), "kms_key": kms_key},
    )]
