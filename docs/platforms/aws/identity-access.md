---
title: AWS Identity & Access (IAM)
platforms: [AWS]
languages: [Bash, Python]
tasks: [Administration, Hardening, Investigation, Assurance]
category: Identity
tags: [aws, iam, roles, policies, access keys, access analyzer, permission boundary, root account, mfa]
aliases: [aws iam audit, who has administratoraccess, aws old access keys, aws credential report, iam access analyzer, aws root account mfa, aws trust policy]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# AWS Identity & Access (IAM)

An IAM request is allowed only if some policy **allows** it and nothing **denies** it. The evaluation layers are: SCP/RCP (Organizations) → resource policy → permission boundary → session policy → identity policy. An explicit `Deny` anywhere wins. Principals are **IAM users** (long-term keys; avoid), **roles** (assumed, temporary credentials) and the account **root user**.

!!! warning "Before you run anything"
    Every command was checked against the AWS CLI reference and AWS API definitions (2026-10-12); this guide does not run them against a live tenant. Commands that change state are marked **change**.

## 1. Root user

The root user can do anything in the account, including closing it, and SCPs do not restrict it in the management account.

```bash
aws iam get-account-summary --query "SummaryMap.{rootMFA:AccountMFAEnabled, rootKeys:AccountAccessKeysPresent, users:Users, roles:Roles}"
```

Required: MFA on root, **no root access keys**, and no daily use. With Organizations, use **centralized root access management** to remove root credentials from member accounts.

## 2. Credential report

One CSV with every IAM user's password, MFA and access-key age and last use:

```bash
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d > credential-report.csv
# Users with active keys older than 90 days
python3 - <<'PY'
import csv, datetime as dt
now = dt.datetime.now(dt.timezone.utc)
for r in csv.DictReader(open("credential-report.csv")):
    for k in ("1", "2"):
        if r[f"access_key_{k}_active"] == "true":
            age = (now - dt.datetime.fromisoformat(r[f"access_key_{k}_last_rotated"])).days
            if age > 90:
                print(r["user"], f"key{k}", age, "days, last used", r[f"access_key_{k}_last_used_date"])
PY
```

## 3. Who is an administrator?

```bash
# Principals with AdministratorAccess attached directly
aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --output table

# Inline and attached policies for one role
aws iam list-attached-role-policies --role-name <role>
aws iam list-role-policies --role-name <role>
aws iam get-role-policy --role-name <role> --policy-name <inline-policy>

# Full authorization picture for the account (large JSON)
aws iam get-account-authorization-details --output json > iam-auth-details.json
```

Look for `"Action": "*"` with `"Resource": "*"`, and for the escalation actions `iam:PassRole`, `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`, `iam:CreateAccessKey` and `lambda:UpdateFunctionCode`.

## 4. Role trust policies

The **trust policy** decides who can assume a role. A wildcard or an unknown external account is a backdoor.

```bash
aws iam list-roles --query "Roles[].{name:RoleName, trust:AssumeRolePolicyDocument.Statement[].Principal}" --output json
aws iam get-role --role-name <role> --query Role.AssumeRolePolicyDocument
```

Cross-account trust for third parties should require an `sts:ExternalId` condition.

## 5. IAM Access Analyzer

```bash
# change: create an organization-wide analyzer for external access (once, delegated admin)
aws accessanalyzer create-analyzer --analyzer-name org-external --type ORGANIZATION

aws accessanalyzer list-analyzers --output table
aws accessanalyzer list-findings-v2 --analyzer-arn <arn> --filter '{"status":{"eq":["ACTIVE"]}}' \
  --query "findings[].{resource:resource, type:resourceType, principal:principal, public:isPublic}" --output table
```

Access Analyzer flags S3 buckets, KMS keys, roles, Lambda functions, secrets and snapshots shared outside your zone of trust. An **unused access** analyzer (paid) lists unused roles, keys and permissions.

## 6. Last-used data: remove what nobody uses

```bash
aws iam get-role --role-name <role> --query "Role.RoleLastUsed"
job=$(aws iam generate-service-last-accessed-details --arn arn:aws:iam::111122223333:role/<role> --query JobId --output text)
aws iam get-service-last-accessed-details --job-id "$job" \
  --query "ServicesLastAccessed[?TotalAuthenticatedEntities==\`0\`].ServiceNamespace" --output text
```

## 7. Test a permission without using it

```bash
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111122223333:role/<role> \
  --action-names s3:GetObject ec2:TerminateInstances --resource-arns "arn:aws:s3:::bucket/*" \
  --query "EvaluationResults[].{action:EvalActionName, decision:EvalDecision}" --output table
```

The simulator does not evaluate SCPs from other accounts or every resource policy. Treat `allowed` as "probably".

## 8. Change access (change)

```bash
aws iam update-access-key --user-name <user> --access-key-id <AKIA...> --status Inactive
aws iam delete-access-key --user-name <user> --access-key-id <AKIA...>
aws iam detach-role-policy --role-name <role> --policy-arn <arn>
aws iam put-role-permissions-boundary --role-name <role> --permissions-boundary <arn>
```

Grant through **IAM Identity Center permission sets** and roles, scoped by **permission boundaries** for anyone who can create roles.

## Related

- [Persistence & threat hunting](persistence-hunting.md)
- [Concept: IAM and PAM](../../fundamentals/concepts/identity-access-management.md)
- [Troubleshooting → AccessDenied](troubleshooting.md#1-accessdenied-and-authentication-errors)

## Sources

- [Policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [Credential reports](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html)
- [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
