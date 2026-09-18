"""
Tests using moto (mocked AWS) — no real AWS account or credentials needed.
Run with: pytest tests/
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import boto3
import pytest
from moto import mock_aws

from aws_client import AWSClients
from scanners.s3_scanner import scan_s3
from scanners.iam_scanner import scan_iam
from scanners.ec2_scanner import scan_ec2


@mock_aws
def test_s3_public_bucket_detected():
    clients = AWSClients(region="us-east-1")
    s3 = clients.s3()
    s3.create_bucket(Bucket="my-public-bucket")
    s3.put_bucket_acl(
        Bucket="my-public-bucket",
        AccessControlPolicy={
            "Grants": [{
                "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ",
            }],
            "Owner": {"ID": s3.get_bucket_acl(Bucket="my-public-bucket")["Owner"]["ID"]},
        },
    )

    findings = scan_s3(clients)
    rule_ids = [f.rule_id for f in findings]
    assert "S3-001" in rule_ids  # public bucket caught
    assert "S3-002" in rule_ids  # no encryption caught
    assert "S3-003" in rule_ids  # no versioning caught


@mock_aws
def test_s3_secure_bucket_clean():
    clients = AWSClients(region="us-east-1")
    s3 = clients.s3()
    s3.create_bucket(Bucket="my-secure-bucket")
    s3.put_bucket_encryption(
        Bucket="my-secure-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_versioning(Bucket="my-secure-bucket", VersioningConfiguration={"Status": "Enabled"})
    s3.put_public_access_block(
        Bucket="my-secure-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )

    findings = scan_s3(clients)
    assert findings == []


@mock_aws
def test_iam_wildcard_admin_policy_detected():
    clients = AWSClients(region="us-east-1")
    iam = clients.iam()
    iam.create_user(UserName="risky-user")
    iam.put_user_policy(
        UserName="risky-user",
        PolicyName="FullAdmin",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
    )

    findings = scan_iam(clients)
    rule_ids = [f.rule_id for f in findings]
    assert "IAM-003" in rule_ids


@mock_aws
def test_ec2_open_ssh_detected():
    clients = AWSClients(region="us-east-1")
    ec2 = clients.ec2()
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg = ec2.create_security_group(GroupName="open-ssh", Description="test", VpcId=vpc["VpcId"])
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    findings = scan_ec2(clients)
    rule_ids = [f.rule_id for f in findings]
    assert "EC2-001" in rule_ids


@mock_aws
def test_ec2_locked_down_sg_clean():
    clients = AWSClients(region="us-east-1")
    ec2 = clients.ec2()
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    ec2.create_security_group(GroupName="locked-down", Description="test", VpcId=vpc["VpcId"])
    # no ingress rules added — should be clean (default SG check only fires if rules exist)

    findings = scan_ec2(clients)
    assert not any(f.resource.startswith("locked-down") for f in findings)
