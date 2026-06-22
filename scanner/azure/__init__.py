try:
    from azure.identity import DefaultAzureCredential  # noqa: F401
    from azure.mgmt.storage import StorageManagementClient  # noqa: F401
    from azure.mgmt.network import NetworkManagementClient  # noqa: F401
    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False
