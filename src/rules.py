"""
Rule definitions loosely based on the CIS AWS Foundations Benchmark
(free, public PDF from cisecurity.org). Each rule has an id, title,
severity, and the CIS control it maps to, so your report can cite a
real standard instead of ad-hoc checks.
"""
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_SCORE = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    resource: str
    detail: str
    remediation: str
    cis_control: str

    @property
    def score(self) -> int:
        return SEVERITY_SCORE[self.severity]


# Central registry so main.py / report_generator.py can look up rule metadata
RULES = {
    "S3-001": dict(
        title="S3 bucket is publicly readable/writable",
        severity=Severity.CRITICAL,
        cis_control="CIS 2.1.5 - Ensure S3 buckets are not publicly accessible",
        remediation="Enable S3 Block Public Access at the bucket or account level; "
                    "remove public grants from the bucket ACL and policy.",
    ),
    "S3-002": dict(
        title="S3 bucket does not have encryption enabled",
        severity=Severity.MEDIUM,
        cis_control="CIS 2.1.1 - Ensure S3 buckets employ encryption-at-rest",
        remediation="Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
    ),
    "S3-003": dict(
        title="S3 bucket does not have versioning enabled",
        severity=Severity.LOW,
        cis_control="CIS 2.1.3 - Ensure S3 bucket versioning is enabled",
        remediation="Enable versioning so accidental deletes/overwrites are recoverable.",
    ),
    "IAM-001": dict(
        title="IAM user has an access key older than 90 days",
        severity=Severity.HIGH,
        cis_control="CIS 1.14 - Ensure access keys are rotated every 90 days or less",
        remediation="Rotate the access key; delete it if the user/application no longer needs it.",
    ),
    "IAM-002": dict(
        title="IAM user has console access without MFA enabled",
        severity=Severity.CRITICAL,
        cis_control="CIS 1.10 - Ensure MFA is enabled for all IAM users with console access",
        remediation="Enable a virtual or hardware MFA device for this user immediately.",
    ),
    "IAM-003": dict(
        title="IAM user has an attached policy granting '*:*' (full admin)",
        severity=Severity.HIGH,
        cis_control="CIS 1.16 - Ensure IAM policies are attached only to groups or roles",
        remediation="Replace broad wildcard permissions with least-privilege policies scoped "
                    "to only the actions/resources the user actually needs.",
    ),
    "IAM-004": dict(
        title="IAM access key is unused for 90+ days but still active",
        severity=Severity.MEDIUM,
        cis_control="CIS 1.12 - Ensure credentials unused for 90 days or greater are disabled",
        remediation="Deactivate or delete the unused access key.",
    ),
    "EC2-001": dict(
        title="Security group allows unrestricted ingress (0.0.0.0/0) on port 22 (SSH)",
        severity=Severity.CRITICAL,
        cis_control="CIS 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
        remediation="Restrict SSH ingress to known IP ranges or require a bastion/VPN.",
    ),
    "EC2-002": dict(
        title="Security group allows unrestricted ingress (0.0.0.0/0) on port 3389 (RDP)",
        severity=Severity.CRITICAL,
        cis_control="CIS 5.3 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
        remediation="Restrict RDP ingress to known IP ranges or require a bastion/VPN.",
    ),
    "EC2-003": dict(
        title="Security group allows unrestricted ingress on an uncommon high-risk port",
        severity=Severity.HIGH,
        cis_control="CIS 5.1 - Ensure security groups restrict ingress to required ports only",
        remediation="Close the port or restrict the source CIDR to only what's required.",
    ),
    "EC2-004": dict(
        title="Default security group allows traffic (should be locked down)",
        severity=Severity.MEDIUM,
        cis_control="CIS 5.4 - Ensure the default security group restricts all traffic",
        remediation="Remove all inbound/outbound rules from the default security group in every VPC.",
    ),
}


def make_finding(rule_id: str, resource: str, detail: str) -> Finding:
    meta = RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        title=meta["title"],
        severity=meta["severity"],
        resource=resource,
        detail=detail,
        remediation=meta["remediation"],
        cis_control=meta["cis_control"],
    )
