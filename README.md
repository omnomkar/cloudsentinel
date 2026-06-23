# CloudSentinel

CloudSentinel is a cloud misconfiguration scanner. It runs read-only checks against
AWS and Azure resources and reports findings as JSON and Markdown.

## CIS benchmark mappings

- AWS checks are mapped to **CIS Amazon Web Services Foundations Benchmark** control IDs.
- Azure checks are mapped to **CIS Microsoft Azure Foundations Benchmark v1.4.0** (released
  11-26-2021) control IDs.

All Azure mappings in [`scanner/reporter.py`](scanner/reporter.py) are verified against the v1.4.0
document specifically. If a check has no matching control in v1.4.0, it is left unmapped
(rendered as "N/A" in reports) rather than assigned a plausible-looking but incorrect
number. See the `CIS_MAPPING` table in `scanner/reporter.py` for the full list.
