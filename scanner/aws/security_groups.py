from typing import List
from scanner import Finding


def run_security_group_checks(client, region: str, reference_time=None) -> List[Finding]:
    findings = []
    paginator = client.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", sg_id)
            findings.extend(_check_ssh_open(sg, sg_id, sg_name, region))
            findings.extend(_check_rdp_open(sg, sg_id, sg_name, region))
            findings.extend(_check_unrestricted_egress(sg, sg_id, sg_name, region))
            findings.extend(_check_overly_permissive(sg, sg_id, sg_name, region))
    return findings


def _is_open_to_world(rule: dict) -> bool:
    for cidr in rule.get("IpRanges", []):
        if cidr.get("CidrIp") == "0.0.0.0/0":
            return True
    for cidr6 in rule.get("Ipv6Ranges", []):
        if cidr6.get("CidrIpv6") == "::/0":
            return True
    return False


def _port_in_range(rule: dict, port: int) -> bool:
    from_port = rule.get("FromPort", 0)
    to_port = rule.get("ToPort", 65535)
    if from_port == -1 and to_port == -1:
        return True
    return from_port <= port <= to_port


def _check_ssh_open(sg: dict, sg_id: str, sg_name: str, region: str) -> List[Finding]:
    is_open = any(
        _is_open_to_world(rule) and _port_in_range(rule, 22)
        for rule in sg.get("IpPermissions", [])
        if rule.get("IpProtocol") in ("tcp", "-1")
    )
    return [Finding(
        resource_id=sg_id,
        resource_type="AWS::EC2::SecurityGroup",
        check_id="SG_SSH_OPEN_TO_WORLD",
        check_name="Security group allows SSH (port 22) from 0.0.0.0/0",
        severity="critical",
        status="FAIL" if is_open else "PASS",
        region=region,
        cloud="aws",
        remediation="Restrict SSH access to known IP ranges instead of 0.0.0.0/0.",
        details={"sg_name": sg_name},
    )]


def _check_rdp_open(sg: dict, sg_id: str, sg_name: str, region: str) -> List[Finding]:
    is_open = any(
        _is_open_to_world(rule) and _port_in_range(rule, 3389)
        for rule in sg.get("IpPermissions", [])
        if rule.get("IpProtocol") in ("tcp", "-1")
    )
    return [Finding(
        resource_id=sg_id,
        resource_type="AWS::EC2::SecurityGroup",
        check_id="SG_RDP_OPEN_TO_WORLD",
        check_name="Security group allows RDP (port 3389) from 0.0.0.0/0",
        severity="critical",
        status="FAIL" if is_open else "PASS",
        region=region,
        cloud="aws",
        remediation="Restrict RDP access to known IP ranges instead of 0.0.0.0/0.",
        details={"sg_name": sg_name},
    )]


def _check_unrestricted_egress(sg: dict, sg_id: str, sg_name: str, region: str) -> List[Finding]:
    is_open = any(
        _is_open_to_world(rule) and rule.get("IpProtocol") == "-1"
        for rule in sg.get("IpPermissionsEgress", [])
    )
    return [Finding(
        resource_id=sg_id,
        resource_type="AWS::EC2::SecurityGroup",
        check_id="SG_UNRESTRICTED_EGRESS",
        check_name="Security group allows unrestricted egress to 0.0.0.0/0",
        severity="medium",
        status="FAIL" if is_open else "PASS",
        region=region,
        cloud="aws",
        remediation="Restrict egress rules to specific destinations and ports.",
        details={"sg_name": sg_name},
    )]


def _check_overly_permissive(sg: dict, sg_id: str, sg_name: str, region: str) -> List[Finding]:
    is_permissive = any(
        _is_open_to_world(rule) and (rule.get("ToPort", 0) - rule.get("FromPort", 0)) > 1024
        for rule in sg.get("IpPermissions", [])
        if rule.get("IpProtocol") not in ("-1",)
        and rule.get("FromPort") is not None
        and rule.get("ToPort") is not None
    )
    return [Finding(
        resource_id=sg_id,
        resource_type="AWS::EC2::SecurityGroup",
        check_id="SG_OVERLY_PERMISSIVE",
        check_name="Security group allows a port range wider than 1024 ports from 0.0.0.0/0",
        severity="high",
        status="FAIL" if is_permissive else "PASS",
        region=region,
        cloud="aws",
        remediation="Narrow the port range in security group inbound rules to only required ports.",
        details={"sg_name": sg_name},
    )]
