"""Scans IAM users for missing MFA, stale/unused access keys, and overly broad policies."""
import json
from datetime import datetime, timezone
from rules import make_finding

KEY_ROTATION_DAYS = 90
KEY_UNUSED_DAYS = 90


def scan_iam(clients) -> list:
    iam = clients.iam()
    findings = []

    users = iam.list_users().get("Users", [])
    now = datetime.now(timezone.utc)

    for user in users:
        username = user["UserName"]

        findings += _check_mfa(iam, username)
        findings += _check_access_keys(iam, username, now)
        findings += _check_wildcard_policies(iam, username)

    return findings


def _check_mfa(iam, username: str) -> list:
    findings = []
    # Only relevant if the user has a console login profile
    has_console_access = True
    try:
        iam.get_login_profile(UserName=username)
    except iam.exceptions.NoSuchEntityException:
        has_console_access = False

    if has_console_access:
        mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        if not mfa_devices:
            findings.append(make_finding(
                "IAM-002", resource=username,
                detail=f"User '{username}' has console access but no MFA device enabled.",
            ))
    return findings


def _check_access_keys(iam, username: str, now: datetime) -> list:
    findings = []
    keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])

    for key in keys:
        if key["Status"] != "Active":
            continue

        key_id = key["AccessKeyId"]
        age_days = (now - key["CreateDate"]).days

        if age_days > KEY_ROTATION_DAYS:
            findings.append(make_finding(
                "IAM-001", resource=f"{username}/{key_id}",
                detail=f"Access key {key_id} for user '{username}' is {age_days} days old.",
            ))

        try:
            last_used = iam.get_access_key_last_used(AccessKeyId=key_id)
            last_used_date = last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate")
            if last_used_date:
                idle_days = (now - last_used_date).days
                if idle_days > KEY_UNUSED_DAYS:
                    findings.append(make_finding(
                        "IAM-004", resource=f"{username}/{key_id}",
                        detail=f"Access key {key_id} for user '{username}' unused for {idle_days} days.",
                    ))
        except Exception:
            pass  # last-used data not always available (e.g. never used)

    return findings


def _check_wildcard_policies(iam, username: str) -> list:
    findings = []

    # inline policies
    for policy_name in iam.list_user_policies(UserName=username).get("PolicyNames", []):
        doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)["PolicyDocument"]
        if _grants_full_admin(doc):
            findings.append(make_finding(
                "IAM-003", resource=username,
                detail=f"User '{username}' has inline policy '{policy_name}' granting '*' on '*'.",
            ))

    # attached managed policies
    attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
    for policy in attached:
        if policy["PolicyName"] == "AdministratorAccess":
            findings.append(make_finding(
                "IAM-003", resource=username,
                detail=f"User '{username}' has the AWS-managed 'AdministratorAccess' policy attached.",
            ))

    return findings


def _grants_full_admin(policy_doc: dict) -> bool:
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        action = stmt.get("Action")
        resource = stmt.get("Resource")
        actions = [action] if isinstance(action, str) else (action or [])
        resources = [resource] if isinstance(resource, str) else (resource or [])
        if "*" in actions and "*" in resources:
            return True
    return False
