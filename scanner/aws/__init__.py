from typing import List, Optional
from datetime import datetime
from scanner import Finding
from scanner.aws.s3 import run_s3_checks
from scanner.aws.iam import run_iam_checks
from scanner.aws.cloudtrail import run_cloudtrail_checks
from scanner.aws.security_groups import run_security_group_checks


def run_all_aws_checks(session, region: str, reference_time: Optional[datetime] = None, endpoint_url: Optional[str] = None) -> List[Finding]:
    client_kwargs: dict = {"region_name": region}
    if endpoint_url:
        client_kwargs["endpoint_url"] = endpoint_url
    s3_client = session.client("s3", **client_kwargs)
    iam_client = session.client("iam", **client_kwargs)
    cloudtrail_client = session.client("cloudtrail", **client_kwargs)
    ec2_client = session.client("ec2", **client_kwargs)

    findings = []
    findings.extend(run_s3_checks(s3_client, region, reference_time))
    findings.extend(run_iam_checks(iam_client, region, reference_time))
    findings.extend(run_cloudtrail_checks(cloudtrail_client, region, reference_time, s3_client=s3_client))
    findings.extend(run_security_group_checks(ec2_client, region, reference_time))
    return findings
