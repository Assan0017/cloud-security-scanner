"""
Generates a sample report using mocked AWS resources (via moto) seeded
with realistic misconfigurations — so you can see exactly what a real
scan's output looks like without needing an AWS account.

Run: python demo_scan.py
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from moto import mock_aws
from aws_client import AWSClients
from scanners.s3_scanner import scan_s3
from scanners.iam_scanner import scan_iam
from scanners.ec2_scanner import scan_ec2
from report_generator import generate_html_report, compute_risk_score


@mock_aws
def seed_and_scan():
    clients = AWSClients(region="us-east-1")
    s3 = clients.s3()
    iam = clients.iam()
    ec2 = clients.ec2()

    # --- seed a few S3 buckets ---
    s3.create_bucket(Bucket="company-public-assets")
    owner_id = s3.get_bucket_acl(Bucket="company-public-assets")["Owner"]["ID"]
    s3.put_bucket_acl(
        Bucket="company-public-assets",
        AccessControlPolicy={
            "Grants": [{
                "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ",
            }],
            "Owner": {"ID": owner_id},
        },
    )

    s3.create_bucket(Bucket="backups-secure")
    s3.put_bucket_encryption(
        Bucket="backups-secure",
        ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
    )
    s3.put_bucket_versioning(Bucket="backups-secure", VersioningConfiguration={"Status": "Enabled"})
    s3.put_public_access_block(
        Bucket="backups-secure",
        PublicAccessBlockConfiguration={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                         "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
    )

    # --- seed IAM users ---
    iam.create_user(UserName="dev-alice")
    iam.put_user_policy(
        UserName="dev-alice", PolicyName="TooMuchAccess",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
    )
    iam.create_access_key(UserName="dev-alice")

    iam.create_user(UserName="svc-deploy-bot")

    # --- seed EC2 security groups ---
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg = ec2.create_security_group(GroupName="web-servers", Description="demo", VpcId=vpc["VpcId"])
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    )

    # --- run all scanners ---
    findings = scan_s3(clients) + scan_iam(clients) + scan_ec2(clients)
    risk = compute_risk_score(findings)

    out_dir = os.path.join(os.path.dirname(__file__), "reports")
    os.makedirs(out_dir, exist_ok=True)
    html_path = os.path.join(out_dir, "demo_report.html")
    generate_html_report(findings, account_id="123456789012 (demo)", output_path=html_path)

    print(f"{len(findings)} findings — risk grade {risk['grade']} ({risk['normalized']}/100)")
    print(f"Sample report written to {html_path}")


if __name__ == "__main__":
    seed_and_scan()
