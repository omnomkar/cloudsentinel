from typing import List
from scanner import Finding


def run_storage_checks(client, reference_time=None) -> List[Finding]:
    findings = []
    accounts = client.storage_accounts.list()

    for account in accounts:
        findings.extend(_check_public_blob_access(account))
        findings.extend(_check_secure_transfer(account))
        findings.extend(_check_cmk_encryption(account))
        findings.extend(_check_network_access(account))

    return findings


def _check_public_blob_access(account) -> List[Finding]:
    allow_public = getattr(account, "allow_blob_public_access", None)
    status = "PASS" if allow_public is False else "FAIL"

    return [Finding(
        resource_id=account.id,
        resource_type="Microsoft.Storage/storageAccounts",
        check_id="AZURE_STORAGE_PUBLIC_BLOB_ACCESS",
        check_name="Storage account allows public access to blob containers",
        severity="critical",
        status=status,
        region=account.location,
        cloud="azure",
        remediation="Set 'Allow Blob Public Access' to Disabled on the storage account.",
        details={"account_name": account.name},
    )]


def _check_secure_transfer(account) -> List[Finding]:
    secure_transfer = getattr(account, "enable_https_traffic_only", None)
    status = "PASS" if secure_transfer is True else "FAIL"

    return [Finding(
        resource_id=account.id,
        resource_type="Microsoft.Storage/storageAccounts",
        check_id="AZURE_STORAGE_SECURE_TRANSFER",
        check_name="Storage account does not enforce secure transfer (HTTPS-only)",
        severity="high",
        status=status,
        region=account.location,
        cloud="azure",
        remediation="Enable 'Secure transfer required' on the storage account to enforce HTTPS-only access.",
        details={"account_name": account.name},
    )]


def _check_cmk_encryption(account) -> List[Finding]:
    encryption = getattr(account, "encryption", None)
    key_source = getattr(encryption, "key_source", None) if encryption else None
    status = "PASS" if key_source == "Microsoft.Keyvault" else "FAIL"

    return [Finding(
        resource_id=account.id,
        resource_type="Microsoft.Storage/storageAccounts",
        check_id="AZURE_STORAGE_CMK_ENCRYPTION",
        check_name="Storage account is not encrypted at rest with a customer-managed key",
        severity="low",
        status=status,
        region=account.location,
        cloud="azure",
        remediation="Configure encryption at rest with a customer-managed key (CMK) in Azure Key Vault if required by policy.",
        details={"account_name": account.name, "key_source": key_source},
    )]


def _check_network_access(account) -> List[Finding]:
    network_rule_set = getattr(account, "network_rule_set", None)
    default_action = getattr(network_rule_set, "default_action", None) if network_rule_set else None
    status = "PASS" if default_action == "Deny" else "FAIL"

    return [Finding(
        resource_id=account.id,
        resource_type="Microsoft.Storage/storageAccounts",
        check_id="AZURE_STORAGE_NETWORK_ACCESS_ALL",
        check_name="Storage account allows access from all networks",
        severity="high",
        status=status,
        region=account.location,
        cloud="azure",
        remediation="Restrict network access with firewall rules limiting access to specific VNets or IP ranges, and set the default action to Deny.",
        details={"account_name": account.name, "default_action": default_action},
    )]
