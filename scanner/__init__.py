from dataclasses import dataclass, field
from typing import Any


VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_STATUSES = {"FAIL", "PASS"}
VALID_CLOUDS = {"aws", "azure"}


@dataclass
class Finding:
    resource_id: str
    resource_type: str
    check_id: str
    check_name: str
    severity: str
    status: str
    region: str
    cloud: str
    remediation: str
    details: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{self.severity}'. Must be one of: {VALID_SEVERITIES}")
        if self.status not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{self.status}'. Must be one of: {VALID_STATUSES}")
        if self.cloud not in VALID_CLOUDS:
            raise ValueError(f"Invalid cloud '{self.cloud}'. Must be one of: {VALID_CLOUDS}")
