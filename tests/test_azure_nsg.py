from types import SimpleNamespace
from unittest.mock import MagicMock

from scanner.azure.nsg import run_nsg_checks


REGION = "eastus"


def make_rule(
    direction="Inbound",
    access="Allow",
    protocol="Tcp",
    source_address_prefix="*",
    destination_port_range="22",
    destination_address_prefix=None,
):
    return SimpleNamespace(
        direction=direction,
        access=access,
        protocol=protocol,
        source_address_prefix=source_address_prefix,
        source_address_prefixes=None,
        destination_address_prefix=destination_address_prefix,
        destination_address_prefixes=None,
        destination_port_range=destination_port_range,
        destination_port_ranges=None,
    )


def make_nsg(name="test-nsg", security_rules=None):
    return SimpleNamespace(
        id=f"/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/{name}",
        name=name,
        location=REGION,
        security_rules=security_rules or [],
    )


def make_client(nsgs):
    client = MagicMock()
    client.network_security_groups.list_all.return_value = nsgs
    return client


class TestSshOpen:
    def test_fail_when_ssh_open_to_world(self):
        rule = make_rule(destination_port_range="22", source_address_prefix="0.0.0.0/0")
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_SSH_OPEN_TO_WORLD"]
        assert match[0].status == "FAIL"

    def test_fail_when_ssh_open_via_internet_tag(self):
        rule = make_rule(destination_port_range="22", source_address_prefix="Internet")
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_SSH_OPEN_TO_WORLD"]
        assert match[0].status == "FAIL"

    def test_pass_when_ssh_restricted_to_specific_ip(self):
        rule = make_rule(destination_port_range="22", source_address_prefix="10.0.0.0/24")
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_SSH_OPEN_TO_WORLD"]
        assert match[0].status == "PASS"

    def test_pass_when_rule_is_deny(self):
        rule = make_rule(destination_port_range="22", source_address_prefix="*", access="Deny")
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_SSH_OPEN_TO_WORLD"]
        assert match[0].status == "PASS"

    def test_pass_when_no_rules(self):
        nsg = make_nsg(security_rules=[])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_SSH_OPEN_TO_WORLD"]
        assert match[0].status == "PASS"


class TestRdpOpen:
    def test_fail_when_rdp_open_to_world(self):
        rule = make_rule(destination_port_range="3389", source_address_prefix="*")
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_RDP_OPEN_TO_WORLD"]
        assert match[0].status == "FAIL"

    def test_pass_when_rdp_restricted(self):
        rule = make_rule(destination_port_range="3389", source_address_prefix="192.168.1.0/24")
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_RDP_OPEN_TO_WORLD"]
        assert match[0].status == "PASS"


class TestWidePortRange:
    def test_fail_when_full_range_open(self):
        rule = make_rule(destination_port_range="0-65535", source_address_prefix="*")
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_WIDE_PORT_RANGE"]
        assert match[0].status == "FAIL"

    def test_fail_when_wildcard_port_range(self):
        rule = make_rule(destination_port_range="*", source_address_prefix="*")
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_WIDE_PORT_RANGE"]
        assert match[0].status == "FAIL"

    def test_pass_when_narrow_range(self):
        rule = make_rule(destination_port_range="443", source_address_prefix="*")
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_WIDE_PORT_RANGE"]
        assert match[0].status == "PASS"

    def test_pass_when_wide_range_not_open_to_world(self):
        rule = make_rule(destination_port_range="0-65535", source_address_prefix="10.0.0.0/8")
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_WIDE_PORT_RANGE"]
        assert match[0].status == "PASS"


class TestUnrestrictedEgress:
    def test_fail_when_outbound_allow_all_to_internet(self):
        rule = make_rule(
            direction="Outbound",
            access="Allow",
            protocol="*",
            source_address_prefix=None,
            destination_address_prefix="0.0.0.0/0",
            destination_port_range="*",
        )
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_UNRESTRICTED_EGRESS"]
        assert match[0].status == "FAIL"

    def test_pass_when_egress_restricted_to_specific_destination(self):
        rule = make_rule(
            direction="Outbound",
            access="Allow",
            protocol="*",
            source_address_prefix=None,
            destination_address_prefix="10.0.1.0/24",
            destination_port_range="*",
        )
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_UNRESTRICTED_EGRESS"]
        assert match[0].status == "PASS"

    def test_pass_when_egress_rule_is_deny(self):
        rule = make_rule(
            direction="Outbound",
            access="Deny",
            protocol="*",
            source_address_prefix=None,
            destination_address_prefix="0.0.0.0/0",
            destination_port_range="*",
        )
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_UNRESTRICTED_EGRESS"]
        assert match[0].status == "PASS"

    def test_pass_when_egress_protocol_restricted(self):
        rule = make_rule(
            direction="Outbound",
            access="Allow",
            protocol="Tcp",
            source_address_prefix=None,
            destination_address_prefix="0.0.0.0/0",
            destination_port_range="443",
        )
        nsg = make_nsg(security_rules=[rule])
        findings = run_nsg_checks(make_client([nsg]))
        match = [f for f in findings if f.check_id == "AZURE_NSG_UNRESTRICTED_EGRESS"]
        assert match[0].status == "PASS"


class TestRunNsgChecks:
    def test_returns_findings_for_every_nsg(self):
        nsg1 = make_nsg(name="nsg1", security_rules=[])
        nsg2 = make_nsg(name="nsg2", security_rules=[])
        findings = run_nsg_checks(make_client([nsg1, nsg2]))
        assert len({f.resource_id for f in findings}) == 2
        assert len(findings) == 8  # 4 checks x 2 nsgs

    def test_no_nsgs_returns_no_findings(self):
        findings = run_nsg_checks(make_client([]))
        assert findings == []
