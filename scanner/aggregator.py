from typing import List, Tuple, Dict
from scanner import Finding


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def aggregate(findings: List[Finding]) -> Tuple[List[Finding], Dict]:
    deduped: Dict[tuple, Finding] = {}

    for f in findings:
        key = (f.resource_id, f.check_id)
        if f.status == "PASS":
            if key not in deduped:
                deduped[key] = f
            continue

        existing = deduped.get(key)
        if existing is None or existing.status == "PASS":
            deduped[key] = f
        elif SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[existing.severity]:
            deduped[key] = f

    fail_findings = [f for f in deduped.values() if f.status == "FAIL"]
    sorted_findings = sorted(fail_findings, key=lambda f: SEVERITY_ORDER[f.severity])

    summary = {
        "total": len(sorted_findings),
        "critical": sum(1 for f in sorted_findings if f.severity == "critical"),
        "high": sum(1 for f in sorted_findings if f.severity == "high"),
        "medium": sum(1 for f in sorted_findings if f.severity == "medium"),
        "low": sum(1 for f in sorted_findings if f.severity == "low"),
    }

    return sorted_findings, summary
