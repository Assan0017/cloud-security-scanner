"""
Central place that builds boto3 clients. Uses whatever credentials are
already configured (aws configure, environment variables, or an IAM
role) — the scanner never asks for or stores credentials itself.
"""
import boto3


class AWSClients:
    def __init__(self, region: str = "us-east-1", profile: str | None = None):
        session_kwargs = {"region_name": region}
        if profile:
            session_kwargs["profile_name"] = profile
        self.session = boto3.Session(**session_kwargs)

    def s3(self):
        return self.session.client("s3")

    def iam(self):
        return self.session.client("iam")

    def ec2(self):
        return self.session.client("ec2")

    def sts(self):
        return self.session.client("sts")

    def account_id(self) -> str:
        return self.sts().get_caller_identity()["Account"]
