import argparse
import sys
import boto3
from scanner.aws import run_all_aws_checks
from scanner.aggregator import aggregate
from scanner.reporter import write_reports
from scanner.console import color_enabled, render_report


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def parse_args():
    parser = argparse.ArgumentParser(description="CloudSentinel — cloud misconfiguration scanner")
    parser.add_argument("--cloud", choices=["aws", "azure", "all"], default="aws")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--endpoint-url", default=None, help="LocalStack or custom endpoint URL")
    parser.add_argument("--subscription-id", default=None, help="Azure subscription ID (required for --cloud azure/all)")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default="critical")
    parser.add_argument("--output-dir", default="./reports")
    parser.add_argument(
        "--exclude-checks",
        default="",
        metavar="CHECK_IDS",
        help="Comma-separated check IDs to exclude from findings and the fail-on gate (e.g. CLOUDTRAIL_NO_TRAIL).",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in console output.")
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        raw_findings = []

        if args.cloud in ("aws", "all"):
            session = boto3.Session()
            raw_findings.extend(run_all_aws_checks(session, args.region, endpoint_url=args.endpoint_url))

        if args.cloud in ("azure", "all"):
            if not args.subscription_id:
                print("Error: --subscription-id is required when --cloud is 'azure' or 'all'.", file=sys.stderr)
                sys.exit(2)
            from azure.identity import DefaultAzureCredential
            from scanner.azure import run_all_azure_checks
            credential = DefaultAzureCredential()
            raw_findings.extend(run_all_azure_checks(credential, args.subscription_id))

        findings, summary = aggregate(raw_findings)

        excluded = {c.strip() for c in args.exclude_checks.split(",") if c.strip()}
        excluded_count = 0
        if excluded:
            pre_exclusion_total = len(findings)
            findings = [f for f in findings if f.check_id not in excluded]
            summary = aggregate(findings)[1]
            excluded_count = pre_exclusion_total - len(findings)

        json_path, md_path = write_reports(findings, summary, args.output_dir)

        fail_threshold = SEVERITY_ORDER[args.fail_on]
        has_blocking = any(
            SEVERITY_ORDER[f.severity] <= fail_threshold for f in findings
        )
        blocking_count = sum(
            1 for f in findings if SEVERITY_ORDER[f.severity] <= fail_threshold
        )

        clouds = ["aws"] if args.cloud == "aws" else ["azure"] if args.cloud == "azure" else ["aws", "azure"]
        render_report(
            findings=findings,
            summary=summary,
            clouds=clouds,
            region=args.region,
            endpoint_url=args.endpoint_url,
            excluded_ids=excluded,
            excluded_count=excluded_count,
            json_path=json_path,
            md_path=md_path,
            fail_on=args.fail_on,
            blocking_count=blocking_count,
            has_blocking=has_blocking,
            use_color=color_enabled(args.no_color),
        )

        sys.exit(1 if has_blocking else 0)

    except Exception as e:
        print(f"Scan error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
