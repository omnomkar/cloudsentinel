import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import List, Dict, Tuple
from scanner import Finding


CIS_MAPPING = {
    "S3_PUBLIC_ACCESS_BLOCK": "2.1.5",
    "S3_PUBLIC_ACL": "2.1.5",
    "S3_BUCKET_POLICY_PUBLIC": "2.1.5",
    "S3_ENCRYPTION_AT_REST": "2.1.1",
    "IAM_WILDCARD_ACTION_POLICY": "1.16",
    "IAM_UNUSED_ROLE": "1.16",
    "IAM_ROOT_NO_MFA": "1.5",
    "IAM_ACCESS_KEY_AGE": "1.14",
    "CLOUDTRAIL_NO_TRAIL": "3.1",
    "CLOUDTRAIL_LOGGING_DISABLED": "3.1",
    "CLOUDTRAIL_LOG_VALIDATION_OFF": "3.2",
    "CLOUDTRAIL_S3_BUCKET_NO_ENCRYPT": "3.6",
    "SG_SSH_OPEN_TO_WORLD": "5.2",
    "SG_RDP_OPEN_TO_WORLD": "5.3",
    "SG_UNRESTRICTED_EGRESS": "5.4",
    "SG_OVERLY_PERMISSIVE": "5.4",
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


def write_reports(findings: List[Finding], summary: Dict, output_dir: str) -> Tuple[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"cloudsentinel_report_{ts}"
    json_path = os.path.join(output_dir, f"{base}.json")
    md_path = os.path.join(output_dir, f"{base}.md")

    _write_json(findings, summary, json_path)
    _write_markdown(findings, summary, md_path)

    return json_path, md_path


def _write_json(findings: List[Finding], summary: Dict, path: str) -> None:
    data = {
        "summary": summary,
        "findings": [asdict(f) for f in findings],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)


def _write_markdown(findings: List[Finding], summary: Dict, path: str) -> None:
    lines = [
        "# CloudSentinel Report",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Summary",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| {SEVERITY_EMOJI['critical']} Critical | {summary['critical']} |",
        f"| {SEVERITY_EMOJI['high']} High | {summary['high']} |",
        f"| {SEVERITY_EMOJI['medium']} Medium | {summary['medium']} |",
        f"| {SEVERITY_EMOJI['low']} Low | {summary['low']} |",
        f"| **Total** | **{summary['total']}** |",
        "",
        "## CIS Benchmark Mapping",
        "",
        "| Check ID | CIS Control |",
        "|----------|-------------|",
    ]
    for check_id, cis in CIS_MAPPING.items():
        lines.append(f"| {check_id} | {cis} |")

    lines += ["", "## Findings", ""]

    by_severity = {"critical": [], "high": [], "medium": [], "low": []}
    for f in findings:
        by_severity[f.severity].append(f)

    for severity in ("critical", "high", "medium", "low"):
        sev_findings = by_severity[severity]
        if not sev_findings:
            continue
        emoji = SEVERITY_EMOJI[severity]
        lines.append(f"### {emoji} {severity.capitalize()} ({len(sev_findings)})")
        lines.append("")
        for f in sev_findings:
            cis = CIS_MAPPING.get(f.check_id, "N/A")
            lines += [
                f"#### {f.check_name}",
                f"- **Check ID:** `{f.check_id}`",
                f"- **CIS Control:** {cis}",
                f"- **Resource:** `{f.resource_id}`",
                f"- **Region:** {f.region}",
                f"- **Remediation:** {f.remediation}",
                "",
            ]

    with open(path, "w") as fh:
        fh.write("\n".join(lines))
