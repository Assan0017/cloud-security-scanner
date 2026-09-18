"""Scans EC2 security groups for overly permissive ingress rules."""
from rules import make_finding

HIGH_RISK_PORTS = {
    22: "EC2-001",   # SSH
    3389: "EC2-002",  # RDP
}
OTHER_SENSITIVE_PORTS = {23, 25, 445, 1433, 1521, 3306, 5432, 6379, 9200, 27017}
OPEN_CIDR = "0.0.0.0/0"


def scan_ec2(clients) -> list:
    ec2 = clients.ec2()
    findings = []

    groups = ec2.describe_security_groups().get("SecurityGroups", [])

    for group in groups:
        group_id = group["GroupId"]
        group_name = group.get("GroupName", group_id)
        is_default = group_name == "default"

        opened_any = False

        for perm in group.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            ip_ranges = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") == OPEN_CIDR]

            if not ip_ranges:
                continue

            opened_any = True
            ports_in_range = _ports_in_range(from_port, to_port)

            for port, rule_id in HIGH_RISK_PORTS.items():
                if port in ports_in_range:
                    findings.append(make_finding(
                        rule_id, resource=f"{group_name} ({group_id})",
                        detail=f"Security group '{group_name}' allows 0.0.0.0/0 ingress on port {port}.",
                    ))

            other_hits = ports_in_range & OTHER_SENSITIVE_PORTS
            for port in other_hits:
                findings.append(make_finding(
                    "EC2-003", resource=f"{group_name} ({group_id})",
                    detail=f"Security group '{group_name}' allows 0.0.0.0/0 ingress on sensitive port {port}.",
                ))

        if is_default and opened_any:
            findings.append(make_finding(
                "EC2-004", resource=f"{group_name} ({group_id})",
                detail=f"Default security group '{group_id}' has active ingress rules; it should deny all traffic.",
            ))

    return findings


def _ports_in_range(from_port, to_port) -> set:
    if from_port is None or to_port is None:
        return set(range(0, 65536))  # "all traffic" rule (-1 protocol)
    return set(range(from_port, to_port + 1))
