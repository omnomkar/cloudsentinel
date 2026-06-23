from typing import List
from scanner import Finding


WORLD_SOURCES = {"*", "0.0.0.0/0", "internet", "any"}
WIDE_RANGE_THRESHOLD = 1024


def run_nsg_checks(client, reference_time=None) -> List[Finding]:
    findings = []
    nsgs = client.network_security_groups.list_all()

    for nsg in nsgs:
        findings.extend(_check_ssh_open(nsg))
        findings.extend(_check_rdp_open(nsg))
        findings.extend(_check_wide_port_range(nsg))
        findings.extend(_check_unrestricted_egress(nsg))

    return findings


def _inbound_allow_rules(nsg) -> list:
    return [
        rule for rule in (getattr(nsg, "security_rules", None) or [])
        if getattr(rule, "direction", None) == "Inbound" and getattr(rule, "access", None) == "Allow"
    ]


def _outbound_allow_rules(nsg) -> list:
    return [
        rule for rule in (getattr(nsg, "security_rules", None) or [])
        if getattr(rule, "direction", None) == "Outbound" and getattr(rule, "access", None) == "Allow"
    ]


def _source_prefixes(rule) -> List[str]:
    prefixes = []
    single = getattr(rule, "source_address_prefix", None)
    if single:
        prefixes.append(single)
    multiple = getattr(rule, "source_address_prefixes", None)
    if multiple:
        prefixes.extend(multiple)
    return prefixes


def _destination_prefixes(rule) -> List[str]:
    prefixes = []
    single = getattr(rule, "destination_address_prefix", None)
    if single:
        prefixes.append(single)
    multiple = getattr(rule, "destination_address_prefixes", None)
    if multiple:
        prefixes.extend(multiple)
    return prefixes


def _is_open_to_world(prefixes: List[str]) -> bool:
    return any(p.lower() in WORLD_SOURCES for p in prefixes)


def _destination_port_ranges(rule) -> List[str]:
    ranges = []
    single = getattr(rule, "destination_port_range", None)
    if single:
        ranges.append(single)
    multiple = getattr(rule, "destination_port_ranges", None)
    if multiple:
        ranges.extend(multiple)
    return ranges


def _port_in_range(port_range: str, port: int) -> bool:
    port_range = port_range.strip()
    if port_range == "*":
        return True
    if "-" in port_range:
        start, end = port_range.split("-", 1)
        return int(start) <= port <= int(end)
    return port_range.isdigit() and int(port_range) == port


def _is_wide_range(port_range: str, threshold: int = WIDE_RANGE_THRESHOLD) -> bool:
    port_range = port_range.strip()
    if port_range == "*":
        return True
    if "-" in port_range:
        start, end = port_range.split("-", 1)
        if start.isdigit() and end.isdigit():
            return (int(end) - int(start)) >= threshold
    return False


def _check_ssh_open(nsg) -> List[Finding]:
    is_open = any(
        _is_open_to_world(_source_prefixes(rule))
        and getattr(rule, "protocol", None) in ("Tcp", "*")
        and any(_port_in_range(pr, 22) for pr in _destination_port_ranges(rule))
        for rule in _inbound_allow_rules(nsg)
    )
    return [Finding(
        resource_id=nsg.id,
        resource_type="Microsoft.Network/networkSecurityGroups",
        check_id="AZURE_NSG_SSH_OPEN_TO_WORLD",
        check_name="Network security group allows SSH (port 22) inbound from the Internet",
        severity="critical",
        status="FAIL" if is_open else "PASS",
        region=nsg.location,
        cloud="azure",
        remediation="Restrict inbound SSH access to known IP ranges instead of the Internet / 0.0.0.0/0.",
        details={"nsg_name": nsg.name},
    )]


def _check_rdp_open(nsg) -> List[Finding]:
    is_open = any(
        _is_open_to_world(_source_prefixes(rule))
        and getattr(rule, "protocol", None) in ("Tcp", "*")
        and any(_port_in_range(pr, 3389) for pr in _destination_port_ranges(rule))
        for rule in _inbound_allow_rules(nsg)
    )
    return [Finding(
        resource_id=nsg.id,
        resource_type="Microsoft.Network/networkSecurityGroups",
        check_id="AZURE_NSG_RDP_OPEN_TO_WORLD",
        check_name="Network security group allows RDP (port 3389) inbound from the Internet",
        severity="critical",
        status="FAIL" if is_open else "PASS",
        region=nsg.location,
        cloud="azure",
        remediation="Restrict inbound RDP access to known IP ranges instead of the Internet / 0.0.0.0/0.",
        details={"nsg_name": nsg.name},
    )]


def _check_wide_port_range(nsg) -> List[Finding]:
    is_wide = any(
        _is_open_to_world(_source_prefixes(rule))
        and any(_is_wide_range(pr) for pr in _destination_port_ranges(rule))
        for rule in _inbound_allow_rules(nsg)
    )
    return [Finding(
        resource_id=nsg.id,
        resource_type="Microsoft.Network/networkSecurityGroups",
        check_id="AZURE_NSG_WIDE_PORT_RANGE",
        check_name="Network security group allows a wide inbound port range from the Internet",
        severity="high",
        status="FAIL" if is_wide else "PASS",
        region=nsg.location,
        cloud="azure",
        remediation="Narrow inbound port ranges to only the specific ports required instead of a broad range.",
        details={"nsg_name": nsg.name},
    )]


def _check_unrestricted_egress(nsg) -> List[Finding]:
    is_open = any(
        _is_open_to_world(_destination_prefixes(rule))
        and getattr(rule, "protocol", None) == "*"
        for rule in _outbound_allow_rules(nsg)
    )
    return [Finding(
        resource_id=nsg.id,
        resource_type="Microsoft.Network/networkSecurityGroups",
        check_id="AZURE_NSG_UNRESTRICTED_EGRESS",
        check_name="Network security group allows unrestricted outbound access to the Internet",
        severity="medium",
        status="FAIL" if is_open else "PASS",
        region=nsg.location,
        cloud="azure",
        remediation="Restrict egress rules to specific destinations and ports instead of allowing all outbound traffic.",
        details={"nsg_name": nsg.name},
    )]
