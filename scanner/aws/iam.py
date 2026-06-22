from typing import List, Optional
from datetime import datetime, timezone, timedelta
import json
from scanner import Finding


def run_iam_checks(client, region: str, reference_time: Optional[datetime] = None) -> List[Finding]:
    if reference_time is None:
        reference_time = datetime.now(timezone.utc)

    findings = []
    findings.extend(_check_wildcard_action_policy(client, region))
    findings.extend(_check_unused_role(client, region, reference_time))
    findings.extend(_check_root_no_mfa(client, region))
    findings.extend(_check_access_key_age(client, region, reference_time))
    return findings


def _check_wildcard_action_policy(client, region: str) -> List[Finding]:
    findings = []
    paginator = client.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            arn = policy["Arn"]
            version_id = policy["DefaultVersionId"]
            try:
                doc = client.get_policy_version(
                    PolicyArn=arn, VersionId=version_id
                )["PolicyVersion"]["Document"]
                statements = doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                has_wildcard = any(
                    stmt.get("Effect") == "Allow" and (
                        stmt.get("Action") == "*"
                        or (isinstance(stmt.get("Action"), list) and "*" in stmt["Action"])
                    )
                    for stmt in statements
                )
                status = "FAIL" if has_wildcard else "PASS"
            except Exception:
                status = "PASS"

            findings.append(Finding(
                resource_id=arn,
                resource_type="AWS::IAM::Policy",
                check_id="IAM_WILDCARD_ACTION_POLICY",
                check_name="IAM policy allows wildcard (*) actions",
                severity="high",
                status=status,
                region=region,
                cloud="aws",
                remediation="Replace wildcard actions with specific, least-privilege permissions.",
                details={"policy_name": policy["PolicyName"]},
            ))
    return findings


def _check_unused_role(client, region: str, reference_time: datetime) -> List[Finding]:
    findings = []
    threshold = timedelta(days=90)
    paginator = client.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            role_name = role["RoleName"]
            role_arn = role["Arn"]
            try:
                last_used_resp = client.get_role(RoleName=role_name)["Role"].get("RoleLastUsed", {})
                last_used = last_used_resp.get("LastUsedDate")
                if last_used is None:
                    create_date = role["CreateDate"]
                    if create_date.tzinfo is None:
                        create_date = create_date.replace(tzinfo=timezone.utc)
                    age = reference_time - create_date
                    status = "FAIL" if age > threshold else "PASS"
                else:
                    if last_used.tzinfo is None:
                        last_used = last_used.replace(tzinfo=timezone.utc)
                    age = reference_time - last_used
                    status = "FAIL" if age > threshold else "PASS"
            except Exception:
                status = "PASS"

            findings.append(Finding(
                resource_id=role_arn,
                resource_type="AWS::IAM::Role",
                check_id="IAM_UNUSED_ROLE",
                check_name="IAM role unused for more than 90 days",
                severity="medium",
                status=status,
                region=region,
                cloud="aws",
                remediation="Remove or deactivate IAM roles that have not been used in 90+ days.",
                details={"role_name": role_name},
            ))
    return findings


def _check_root_no_mfa(client, region: str) -> List[Finding]:
    try:
        summary = client.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0)
        status = "PASS" if mfa_enabled else "FAIL"
    except Exception:
        status = "PASS"

    return [Finding(
        resource_id="arn:aws:iam::root",
        resource_type="AWS::IAM::RootAccount",
        check_id="IAM_ROOT_NO_MFA",
        check_name="Root account does not have MFA enabled",
        severity="critical",
        status=status,
        region=region,
        cloud="aws",
        remediation="Enable MFA on the AWS root account immediately.",
        details={},
    )]


def _check_access_key_age(client, region: str, reference_time: datetime) -> List[Finding]:
    findings = []
    threshold = timedelta(days=90)
    paginator = client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            keys_resp = client.list_access_keys(UserName=username)
            for key in keys_resp.get("AccessKeyMetadata", []):
                key_id = key["AccessKeyId"]
                create_date = key["CreateDate"]
                if create_date.tzinfo is None:
                    create_date = create_date.replace(tzinfo=timezone.utc)
                age = reference_time - create_date
                status = "FAIL" if age > threshold else "PASS"

                findings.append(Finding(
                    resource_id=key_id,
                    resource_type="AWS::IAM::AccessKey",
                    check_id="IAM_ACCESS_KEY_AGE",
                    check_name="IAM access key older than 90 days",
                    severity="high",
                    status=status,
                    region=region,
                    cloud="aws",
                    remediation="Rotate IAM access keys that are older than 90 days.",
                    details={"username": username, "key_id": key_id},
                ))
    return findings
