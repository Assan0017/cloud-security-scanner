"""Scans S3 buckets for public access, missing encryption, missing versioning."""
from botocore.exceptions import ClientError
from rules import make_finding


def scan_s3(clients) -> list:
    s3 = clients.s3()
    findings = []

    buckets = s3.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]

        # 1. Public access check
        if _is_bucket_public(s3, name):
            findings.append(make_finding(
                "S3-001", resource=name,
                detail=f"Bucket '{name}' has a public ACL grant or bucket policy, "
                       f"or Block Public Access is not fully enabled.",
            ))

        # 2. Encryption check
        if not _has_encryption(s3, name):
            findings.append(make_finding(
                "S3-002", resource=name,
                detail=f"Bucket '{name}' has no default server-side encryption configured.",
            ))

        # 3. Versioning check
        if not _has_versioning(s3, name):
            findings.append(make_finding(
                "S3-003", resource=name,
                detail=f"Bucket '{name}' does not have versioning enabled.",
            ))

    return findings


def _is_bucket_public(s3, name: str) -> bool:
    # Check Block Public Access config first — if all four are True, bucket is safe
    try:
        pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        if all(pab.values()):
            return False
    except ClientError:
        pass  # no PAB config set — fall through to check ACL/policy directly

    try:
        acl = s3.get_bucket_acl(Bucket=name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                return True
    except ClientError:
        pass

    try:
        status = s3.get_bucket_policy_status(Bucket=name)
        if status.get("PolicyStatus", {}).get("IsPublic"):
            return True
    except ClientError:
        pass  # no bucket policy at all is fine

    return False


def _has_encryption(s3, name: str) -> bool:
    try:
        s3.get_bucket_encryption(Bucket=name)
        return True
    except ClientError:
        return False


def _has_versioning(s3, name: str) -> bool:
    try:
        status = s3.get_bucket_versioning(Bucket=name)
        return status.get("Status") == "Enabled"
    except ClientError:
        return False
