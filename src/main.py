"""
Cloud Security Posture Scanner — CLI entry point.

Usage:
    python main.py --region us-east-1 --profile default
    python main.py --region us-east-1 --output reports/my_scan
"""
import argparse
import json
import os
import sys
from datetime import datetime

from aws_client import AWSClients
from scanners.s3_scanner import scan_s3
from scanners.iam_scanner import scan_iam
from scanners.ec2_scanner import scan_ec2
from report_generator import generate_html_report, export_pdf, compute_risk_score


def main():
    parser = argparse.ArgumentParser(description="Scan an AWS account for common misconfigurations.")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--profile", default=None, help="Named AWS CLI profile to use")
    parser.add_argument("--output", default=None, help="Report output path prefix (no extension)")
    args = parser.parse_args()

    print("Connecting to AWS...")
    clients = AWSClients(region=args.region, profile=args.profile)

    try:
        account_id = clients.account_id()
    except Exception as e:
        print(f"Could not authenticate to AWS: {e}")
        print("Run 'aws configure' first, or check your credentials/profile.")
        sys.exit(1)

    print(f"Authenticated. Scanning account {account_id} in region {args.region}...")

    all_findings = []

    print("  Scanning S3 buckets...")
    all_findings += scan_s3(clients)

    print("  Scanning IAM users...")
    all_findings += scan_iam(clients)

    print("  Scanning EC2 security groups...")
    all_findings += scan_ec2(clients)

    risk = compute_risk_score(all_findings)
    print(f"\nScan complete: {len(all_findings)} findings. Risk grade: {risk['grade']} ({risk['normalized']}/100)")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_prefix = args.output or os.path.join(
        os.path.dirname(__file__), "..", "reports", f"scan_{timestamp}"
    )
    os.makedirs(os.path.dirname(output_prefix) or ".", exist_ok=True)

    html_path = f"{output_prefix}.html"
    json_path = f"{output_prefix}.json"

    generate_html_report(all_findings, account_id, html_path)
    print(f"HTML report: {html_path}")

    with open(json_path, "w") as f:
        json.dump([
            {
                "rule_id": fdg.rule_id, "title": fdg.title, "severity": fdg.severity.value,
                "resource": fdg.resource, "detail": fdg.detail,
                "remediation": fdg.remediation, "cis_control": fdg.cis_control,
            }
            for fdg in all_findings
        ], f, indent=2)
    print(f"JSON findings log: {json_path}")

    pdf_path = f"{output_prefix}.pdf"
    if export_pdf(html_path, pdf_path):
        print(f"PDF report: {pdf_path}")
    else:
        print("PDF export skipped (install 'weasyprint' for PDF output — HTML report works standalone).")


if __name__ == "__main__":
    main()
