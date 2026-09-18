# Cloud Security Posture Scanner (AWS)

Scans an AWS account for common misconfigurations across S3, IAM, and
EC2 security groups, scores the findings against a CIS AWS Foundations
Benchmark-style rule set, and outputs an HTML (+ optional PDF) risk
report. This mirrors what commercial CSPM tools (Prisma Cloud, AWS
Security Hub, Wiz) do at a smaller scale.

## What it checks

| Area | Checks |
|---|---|
| **S3** | Public bucket access (ACL/policy/Block Public Access), missing encryption, missing versioning |
| **IAM** | Console users without MFA, access keys older than 90 days, access keys unused 90+ days, wildcard `*:*` admin policies |
| **EC2** | Security groups open to `0.0.0.0/0` on SSH (22), RDP (3389), and other sensitive ports (DB ports, etc.), unrestricted default security groups |

Every finding cites the specific CIS control it maps to, its severity
(CRITICAL/HIGH/MEDIUM/LOW), and a concrete remediation step.

## Project structure

```
cloud-security-scanner/
├── src/
│   ├── aws_client.py       # boto3 session/client factory
│   ├── rules.py            # CIS-mapped rule definitions + severity scoring
│   ├── report_generator.py # HTML report + risk scoring + optional PDF export
│   ├── main.py              # CLI entry point
│   └── scanners/
│       ├── s3_scanner.py
│       ├── iam_scanner.py
│       └── ec2_scanner.py
├── tests/
│   └── test_scanners.py     # tests using moto (mocked AWS) — no real account needed
├── demo_scan.py              # seeds mock AWS data and generates a sample report
├── reports/                  # generated HTML/PDF/JSON reports land here
└── requirements.txt
```

## Try it right now — no AWS account needed

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python demo_scan.py
```

This seeds a **mocked** AWS environment (via the `moto` library) with
realistic misconfigurations — a public S3 bucket, an IAM user with a
wildcard admin policy, and a security group open to SSH/RDP/MySQL —
then runs the real scanner code against it and writes
`reports/demo_report.html`. Open that file in a browser to see exactly
what a real scan's output looks like.

Verify the scanners are correct:

```bash
pytest tests/ -v
```

All 5 tests pass — they assert each scanner catches the specific
misconfiguration it's designed to catch, and stays quiet on secure
resources.

## Running it against a real AWS account (free tier)

1. Create a free AWS account if you don't have one (aws.amazon.com/free).
2. Create an IAM user for yourself with `ReadOnlyAccess` policy attached
   (the scanner never needs write access — it only reads configuration).
3. Run `aws configure` and enter that user's access key/secret (or use
   `aws configure --profile scanner` for a named profile).
4. Run:
   ```bash
   cd src
   python main.py --region us-east-1
   # or: python main.py --region us-east-1 --profile scanner
   ```
5. Check `reports/` for the timestamped HTML, JSON, and (if `weasyprint`
   is installed and working) PDF report.

**Cost:** all of this uses only read-only API calls (`Describe*`,
`List*`, `Get*`), which are free — this will not incur any AWS charges.

## Free ways to improve this further

- **Add more checks**: unencrypted EBS volumes, RDS instances publicly
  accessible, CloudTrail not enabled, root account without MFA — all
  straightforward additions to the `scanners/` pattern already here.
- **Add a Lambda + EventBridge schedule** (free tier covers this
  easily) so the scan runs automatically every day and emails/Slacks
  you a report — this turns it from a script into a real monitoring tool.
- **Add a `--fix` flag** that offers to auto-remediate safe findings
  (e.g., enabling S3 Block Public Access) with a confirmation prompt —
  a strong "automation" talking point in interviews.
- **Multi-account support** — loop over multiple named profiles/accounts
  in one run, like a real CSPM tool would for an organization.
- **Deploy the HTML report to S3 + CloudFront** (free tier) so you have
  a live "dashboard" link, not just a local file, to show recruiters.
- **Add a Terraform file** that intentionally creates a small set of
  misconfigured demo resources in your own free-tier account, so you
  can show a live before/after remediation demo in an interview.

## Resume bullet you can use

> Built a Python CSPM (Cloud Security Posture Management) tool using
> boto3 that scans AWS S3, IAM, and EC2 for misconfigurations against
> CIS Foundations Benchmark controls, generating severity-scored HTML
> risk reports; validated with a moto-based test suite covering 5+
> real-world misconfiguration scenarios.
