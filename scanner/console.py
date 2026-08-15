import os
import sys
from typing import Dict, List, Optional, Sequence

from scanner import Finding
from scanner.reporter import CIS_MAPPING


SEVERITY_ORDER = ("critical", "high", "medium", "low")

_RESET = "\033[0m"
_BOLD = "\033[1m"
_SEVERITY_COLOR = {
    "critical": "\033[31m",  # red
    "high": "\033[33m",      # yellow
    "medium": "\033[36m",    # cyan
    "low": "\033[32m",       # green
}

_SEVERITY_COL_WIDTH = 8
_CHECK_ID_COL_WIDTH = 34
_CIS_COL_WIDTH = 6
_RESOURCE_COL_WIDTH = 46


def color_enabled(no_color_flag: bool, stream=sys.stdout) -> bool:
    if no_color_flag:
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    return stream.isatty()


def _colorize(text: str, severity: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_SEVERITY_COLOR[severity]}{text}{_RESET}"


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    return text[: width - 3] + "..."


def _findings_table(findings: List[Finding], use_color: bool) -> List[str]:
    header = (
        f"{'SEVERITY'.ljust(_SEVERITY_COL_WIDTH)}  "
        f"{'CHECK ID'.ljust(_CHECK_ID_COL_WIDTH)}  "
        f"{'CIS'.ljust(_CIS_COL_WIDTH)}  "
        f"RESOURCE"
    )
    lines = [header, "-" * len(header)]

    for f in findings:
        sev_text = _truncate(f.severity.upper(), _SEVERITY_COL_WIDTH).ljust(_SEVERITY_COL_WIDTH)
        sev_text = _colorize(sev_text, f.severity, use_color)
        check_id = _truncate(f.check_id, _CHECK_ID_COL_WIDTH).ljust(_CHECK_ID_COL_WIDTH)
        cis = _truncate(CIS_MAPPING.get(f.check_id, "N/A"), _CIS_COL_WIDTH).ljust(_CIS_COL_WIDTH)
        resource = _truncate(f.resource_id, _RESOURCE_COL_WIDTH)
        lines.append(f"{sev_text}  {check_id}  {cis}  {resource}")

    return lines


def _summary_lines(summary: Dict, use_color: bool) -> List[str]:
    label_width = max(len(s) for s in SEVERITY_ORDER) + 1
    lines = []
    for severity in SEVERITY_ORDER:
        label = _colorize(f"{severity.upper():<{label_width}}", severity, use_color)
        lines.append(f"  {label} {summary[severity]:>4}")
    lines.append(f"  {'-' * (label_width + 5)}")
    lines.append(f"  {'TOTAL':<{label_width}} {summary['total']:>4}")
    return lines


def render_report(
    findings: List[Finding],
    summary: Dict,
    clouds: Sequence[str],
    region: str,
    endpoint_url: Optional[str],
    excluded_ids: Sequence[str],
    excluded_count: int,
    json_path: str,
    md_path: str,
    fail_on: str,
    blocking_count: int,
    has_blocking: bool,
    use_color: bool,
    stream=sys.stdout,
) -> None:
    lines: List[str] = []

    header = f"CloudSentinel scan — cloud: {', '.join(clouds)} | region: {region}"
    if endpoint_url:
        header += f" | endpoint: {endpoint_url}"
    lines.append(header)
    lines.append("")

    if findings:
        lines.append("Findings:")
        lines.extend(_findings_table(findings, use_color))
    else:
        lines.append("Findings: none")
    lines.append("")

    if excluded_ids:
        lines.append(
            f"Excluded {excluded_count} finding(s) via --exclude-checks: {', '.join(sorted(excluded_ids))}"
        )
        lines.append("")

    lines.append("Summary:")
    lines.extend(_summary_lines(summary, use_color))
    lines.append("")

    lines.append("Reports written:")
    lines.append(f"  JSON:     {json_path}")
    lines.append(f"  Markdown: {md_path}")
    lines.append("")

    if has_blocking:
        msg = f"GATE FAILED: {blocking_count} finding(s) at or above '{fail_on}' threshold."
        if use_color:
            msg = f"{_BOLD}{_SEVERITY_COLOR['critical']}{msg}{_RESET}"
    else:
        msg = f"Gate passed — no findings at or above '{fail_on}' threshold."
        if use_color:
            msg = f"{_BOLD}{_SEVERITY_COLOR['low']}{msg}{_RESET}"
    lines.append(msg)

    stream.write("\n".join(lines) + "\n")
