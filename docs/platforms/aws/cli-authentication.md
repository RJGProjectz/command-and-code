---
title: AWS CLI, SDKs & Authentication
platforms: [AWS]
languages: [Bash, PowerShell, Python]
tasks: [Administration, Automation, Incident Response]
category: Authentication
tags: [aws, aws cli, iam identity center, sso, assume role, sts, access keys, imdsv2, boto3]
aliases: [aws configure sso, aws sts get-caller-identity, aws assume role cli, aws profile, aws credentials file, aws imdsv2 token]
difficulty: basic
verified: false
---

# AWS CLI, SDKs & Authentication

Every AWS API call is signed with credentials: either **long-term access keys** (an IAM user) or **temporary credentials** from AWS STS (IAM Identity Center, an assumed role, an instance profile). Prefer temporary credentials everywhere. The **AWS CLI v2**, **AWS Tools for PowerShell** and **boto3** all read the same profiles and credential chain.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from AWS documentation and not yet lab-tested in this repo. Run read-only commands first. Commands that change state are marked **change**.

## 1. Install and check the tools

```bash
aws --version                         # must be aws-cli/2.x
pip install boto3                     # Python SDK
```

```powershell
Install-Module AWS.Tools.Installer -Scope CurrentUser
Install-AWSToolsModule AWS.Tools.EC2, AWS.Tools.IdentityManagement, AWS.Tools.S3 -CleanUp
```

## 2. Sign in

| Identity | How |
| :--- | :--- |
| Workforce user (recommended) | **IAM Identity Center** (SSO): `aws configure sso`, then `aws sso login --profile <p>` |
| Role in another account | `role_arn` + `source_profile` in `~/.aws/config`, or `aws sts assume-role` |
| EC2, ECS, Lambda workload | Instance profile / task role / execution role; credentials appear automatically |
| CI/CD outside AWS | OIDC federation (`AssumeRoleWithWebIdentity`), no stored keys |
| IAM user access keys | Last resort; rotate every 90 days and never on laptops of admins |

```ini
# ~/.aws/config
[profile prod-admin]
sso_session = corp
sso_account_id = 111122223333
sso_role_name = AdministratorAccess
region = ca-central-1

[sso-session corp]
sso_start_url = https://corp.awsapps.com/start
sso_region = ca-central-1

[profile audit]
role_arn = arn:aws:iam::444455556666:role/SecurityAudit
source_profile = prod-admin
```

## 3. Who am I?

```bash
aws sts get-caller-identity --profile prod-admin
export AWS_PROFILE=prod-admin           # PowerShell: $env:AWS_PROFILE = 'prod-admin'
aws configure list                      # which credential source the CLI resolved
```

```powershell
Set-AWSCredential -ProfileName prod-admin
Get-STSCallerIdentity
```

```python
import boto3
print(boto3.Session(profile_name="prod-admin").client("sts").get_caller_identity())
```

## 4. Assume a role manually

```bash
creds=$(aws sts assume-role --role-arn arn:aws:iam::444455556666:role/SecurityAudit \
  --role-session-name "ir-$(whoami)" --duration-seconds 3600 --query Credentials --output json)
export AWS_ACCESS_KEY_ID=$(echo "$creds" | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo "$creds" | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo "$creds" | jq -r .SessionToken)
```

Use a meaningful `--role-session-name`; it appears in CloudTrail as part of the assumed-role ARN and is how you find your own actions later.

## 5. Credential resolution order

The CLI and SDKs stop at the first source that works:

1. Command-line options (`--profile`, `--region`)
2. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`)
3. Web identity token (`AWS_WEB_IDENTITY_TOKEN_FILE`)
4. SSO / `~/.aws/config` and `~/.aws/credentials`
5. Container credentials (ECS task role)
6. Instance metadata (EC2 instance profile)

Stale environment variables are the most common reason a command runs as the wrong identity.

## 6. Instance metadata (IMDSv2)

On EC2, the instance profile's credentials come from IMDS. **IMDSv2** requires a session token and blocks most SSRF theft; enforce it ([Compute](compute.md#5-enforce-imdsv2)).

```bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Instance-profile credentials used **outside** that instance trigger the GuardDuty finding `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`.

## 7. Known locations

| Path | Contents |
| :--- | :--- |
| `~/.aws/credentials` (`%USERPROFILE%\.aws\credentials`) | Long-term access keys in plain text |
| `~/.aws/config` | Profiles, regions, role chains, SSO settings |
| `~/.aws/sso/cache/` | SSO access tokens (valid up to the session duration) |
| `~/.aws/cli/cache/` | Cached assumed-role credentials |

Treat all of these as credentials. On a compromised workstation, collect them as evidence and then [revoke the sessions](incident-response.md#1-contain-the-identity).

## Related

- [Identity & access (IAM)](identity-access.md)
- [Troubleshooting → AccessDenied](troubleshooting.md#1-accessdenied-and-authentication-errors)
- [Concept: authentication and MFA](../../fundamentals/concepts/authentication-mfa-sso.md)

## Sources

- [Configure the AWS CLI to use IAM Identity Center](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
- [Credential and profile precedence](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-precedence)
- [Use IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
