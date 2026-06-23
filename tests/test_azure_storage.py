from types import SimpleNamespace
from unittest.mock import MagicMock

from scanner.azure.storage import run_storage_checks


REGION = "eastus"


def make_account(
    name="testaccount",
    allow_blob_public_access=True,
    enable_https_traffic_only=False,
    key_source="Microsoft.Storage",
    default_action="Allow",
):
    return SimpleNamespace(
        id=f"/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/{name}",
        name=name,
        location=REGION,
        allow_blob_public_access=allow_blob_public_access,
        enable_https_traffic_only=enable_https_traffic_only,
        encryption=SimpleNamespace(key_source=key_source),
        network_rule_set=SimpleNamespace(default_action=default_action),
    )


def make_client(accounts):
    client = MagicMock()
    client.storage_accounts.list.return_value = accounts
    return client


class TestPublicBlobAccess:
    def test_fail_when_public_access_allowed(self):
        account = make_account(allow_blob_public_access=True)
        findings = run_storage_checks(make_client([account]))
        match = [f for f in findings if f.check_id == "AZURE_STORAGE_PUBLIC_BLOB_ACCESS"]
        assert len(match) == 1
        assert match[0].status == "FAIL"

    def test_pass_when_public_access_disabled(self):
        account = make_account(allow_blob_public_access=False)
        findings = run_storage_checks(make_client([account]))
        match = [f for f in findings if f.check_id == "AZURE_STORAGE_PUBLIC_BLOB_ACCESS"]
        assert match[0].status == "PASS"

    def test_fail_when_attribute_missing(self):
        account = make_account(allow_blob_public_access=True)
        del account.allow_blob_public_access
        findings = run_storage_checks(make_client([account]))
        match = [f for f in findings if f.check_id == "AZURE_STORAGE_PUBLIC_BLOB_ACCESS"]
        assert match[0].status == "FAIL"


class TestSecureTransfer:
    def test_fail_when_https_only_disabled(self):
        account = make_account(enable_https_traffic_only=False)
        findings = run_storage_checks(make_client([account]))
        match = [f for f in findings if f.check_id == "AZURE_STORAGE_SECURE_TRANSFER"]
        assert match[0].status == "FAIL"

    def test_pass_when_https_only_enabled(self):
        account = make_account(enable_https_traffic_only=True)
        findings = run_storage_checks(make_client([account]))
        match = [f for f in findings if f.check_id == "AZURE_STORAGE_SECURE_TRANSFER"]
        assert match[0].status == "PASS"


class TestCmkEncryption:
    def test_fail_when_platform_managed_key(self):
        account = make_account(key_source="Microsoft.Storage")
        findings = run_storage_checks(make_client([account]))
        match = [f for f in findings if f.check_id == "AZURE_STORAGE_CMK_ENCRYPTION"]
        assert match[0].status == "FAIL"
        assert match[0].severity == "low"

    def test_pass_when_customer_managed_key(self):
        account = make_account(key_source="Microsoft.Keyvault")
        findings = run_storage_checks(make_client([account]))
        match = [f for f in findings if f.check_id == "AZURE_STORAGE_CMK_ENCRYPTION"]
        assert match[0].status == "PASS"

    def test_fail_when_encryption_missing(self):
        account = make_account()
        account.encryption = None
        findings = run_storage_checks(make_client([account]))
        match = [f for f in findings if f.check_id == "AZURE_STORAGE_CMK_ENCRYPTION"]
        assert match[0].status == "FAIL"


class TestNetworkAccess:
    def test_fail_when_default_action_allow(self):
        account = make_account(default_action="Allow")
        findings = run_storage_checks(make_client([account]))
        match = [f for f in findings if f.check_id == "AZURE_STORAGE_NETWORK_ACCESS_ALL"]
        assert match[0].status == "FAIL"

    def test_pass_when_default_action_deny(self):
        account = make_account(default_action="Deny")
        findings = run_storage_checks(make_client([account]))
        match = [f for f in findings if f.check_id == "AZURE_STORAGE_NETWORK_ACCESS_ALL"]
        assert match[0].status == "PASS"

    def test_fail_when_network_rule_set_missing(self):
        account = make_account()
        account.network_rule_set = None
        findings = run_storage_checks(make_client([account]))
        match = [f for f in findings if f.check_id == "AZURE_STORAGE_NETWORK_ACCESS_ALL"]
        assert match[0].status == "FAIL"


class TestRunStorageChecks:
    def test_returns_findings_for_every_account(self):
        accounts = [make_account(name="acct1"), make_account(name="acct2")]
        findings = run_storage_checks(make_client(accounts))
        assert len({f.resource_id for f in findings}) == 2
        assert len(findings) == 8  # 4 checks x 2 accounts

    def test_no_accounts_returns_no_findings(self):
        findings = run_storage_checks(make_client([]))
        assert findings == []
