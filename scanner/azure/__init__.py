from typing import List, Optional
from datetime import datetime
from scanner import Finding
from scanner.azure.storage import run_storage_checks
from scanner.azure.nsg import run_nsg_checks

try:
    from azure.identity import DefaultAzureCredential  # noqa: F401
    from azure.mgmt.storage import StorageManagementClient  # noqa: F401
    from azure.mgmt.network import NetworkManagementClient  # noqa: F401
    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False


def run_all_azure_checks(credential, subscription_id: str, reference_time: Optional[datetime] = None) -> List[Finding]:
    if not AZURE_SDK_AVAILABLE:
        raise RuntimeError(
            "Azure SDK packages are not installed. Install requirements.txt (Azure SDK section) to run Azure checks."
        )

    storage_client = StorageManagementClient(credential, subscription_id)
    network_client = NetworkManagementClient(credential, subscription_id)

    findings = []
    findings.extend(run_storage_checks(storage_client, reference_time))
    findings.extend(run_nsg_checks(network_client, reference_time))
    return findings
