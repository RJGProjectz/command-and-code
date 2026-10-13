---
title: AWS Persistence & Threat Hunting
platforms: [AWS]
languages: [Bash, Python]
tasks: [Threat Hunting, Incident Response, Investigation, Detection Engineering]
category: Persistence
tags: [aws, persistence, threat hunting, iam backdoor, access keys, assume role policy, lambda, eventbridge, mitre attack]
aliases: [aws persistence techniques, hunt aws backdoor user, createaccesskey for other user, updateassumerolepolicy backdoor, lambda persistence aws, aws attacker enumeration]
difficulty: advanced
verified: true
last_verified: 2026-10-12
---

# AWS Persistence & Threat Hunting

After stealing a credential, an attacker in AWS wants access that survives key rotation: new identities, new keys on existing identities, trust-policy backdoors, and code that runs on a schedule. Each hunt below uses CloudTrail Lake SQL (adapt to Athena by renaming the table, see [Monitoring](monitoring-logs.md#4-athena-over-s3-logs)).

!!! warning "Before you run anything"
    Every command was checked against the AWS CLI reference and AWS API definitions (2026-10-12); this guide does not run them against a live tenant. Queries are hunting starting points: baseline your own environment before turning any into an alert.

## 1. Technique map

| Technique | ATT&CK | CloudTrail events |
| :--- | :--- | :--- |
| New IAM user / login profile | [T1136.003](https://attack.mitre.org/techniques/T1136/003/) | `CreateUser`, `CreateLoginProfile`, `UpdateLoginProfile` |
| Access key on another user | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | `CreateAccessKey` where caller ≠ target user |
| Trust-policy backdoor (external account can assume a role) | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | `UpdateAssumeRolePolicy`, `CreateRole` |
| Privilege escalation via policy | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | `AttachUserPolicy`, `PutRolePolicy`, `CreatePolicyVersion` with `SetAsDefault` |
| Scheduled code (Lambda + EventBridge) | [T1053](https://attack.mitre.org/techniques/T1053/), [T1648](https://attack.mitre.org/techniques/T1648/) | `CreateFunction*`, `UpdateFunctionCode*`, `PutRule`, `PutTargets`, `AddPermission` |
| Federation backdoor | [T1484.002](https://attack.mitre.org/techniques/T1484/002/) | `CreateSAMLProvider`, `UpdateSAMLProvider`, `CreateOpenIDConnectProvider` |
| Instance user data / SSM documents | [T1651](https://attack.mitre.org/techniques/T1651/) | `ModifyInstanceAttribute` (userData), `CreateDocument`, `SendCommand` |
| Defense evasion | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | `StopLogging`, `DeleteDetector`, `DisableSecurityHub` |

## 2. Hunts

```sql
-- H1: access keys created for someone other than the caller
SELECT eventTime, userIdentity.arn AS caller, element_at(requestParameters, 'userName') AS targetUser, sourceIPAddress
FROM <eds-id>
WHERE eventName = 'CreateAccessKey' AND errorCode IS NULL
  AND element_at(requestParameters, 'userName') IS NOT NULL
  AND userIdentity.arn NOT LIKE concat('%/', element_at(requestParameters, 'userName'))
  AND eventTime > date_add('day', -30, now())
```

```sql
-- H2: trust policies changed or roles created that trust another account
SELECT eventTime, userIdentity.arn, eventName, element_at(requestParameters, 'roleName') AS role,
       element_at(requestParameters, 'policyDocument') AS trust
FROM <eds-id>
WHERE eventName IN ('UpdateAssumeRolePolicy', 'CreateRole') AND errorCode IS NULL
  AND eventTime > date_add('day', -30, now())
```

Review `trust` for account IDs outside your organization and for `"AWS": "*"`.

```sql
-- H3: IAM write activity from principals that rarely do it
SELECT userIdentity.arn, count(*) AS writes, array_agg(DISTINCT eventName) AS events
FROM <eds-id>
WHERE eventSource = 'iam.amazonaws.com' AND readOnly = false AND errorCode IS NULL
  AND eventTime > date_add('day', -7, now())
GROUP BY userIdentity.arn
ORDER BY writes ASC
```

```sql
-- H4: enumeration bursts: many distinct APIs with AccessDenied from one session
SELECT userIdentity.arn, sourceIPAddress, userAgent, count(DISTINCT eventName) AS apis, count(*) AS denied
FROM <eds-id>
WHERE errorCode IN ('AccessDenied', 'Client.UnauthorizedOperation') AND eventTime > date_add('day', -1, now())
GROUP BY userIdentity.arn, sourceIPAddress, userAgent
HAVING count(DISTINCT eventName) > 20
```

```sql
-- H5: activity in regions you do not use
SELECT awsRegion, userIdentity.arn, eventName, count(*) AS n
FROM <eds-id>
WHERE awsRegion NOT IN ('ca-central-1', 'us-east-1') AND readOnly = false
  AND eventTime > date_add('day', -30, now())
GROUP BY 1, 2, 3 ORDER BY n DESC
```

```sql
-- H6: new scheduled or event-driven code
SELECT eventTime, userIdentity.arn, eventName, element_at(requestParameters, 'functionName') AS fn,
       element_at(requestParameters, 'name') AS rule
FROM <eds-id>
WHERE eventName IN ('CreateFunction20150331', 'UpdateFunctionCode20150331v2', 'AddPermission20150331v2', 'PutRule', 'PutTargets')
  AND eventTime > date_add('day', -30, now())
```

Lambda event names carry API version suffixes; check the exact names in your own trail.

## 3. Point-in-time sweep (no logs needed)

```bash
# Users and keys created recently
aws iam list-users --query "Users[?CreateDate>='2026-09-01'].{user:UserName, created:CreateDate}" --output table
for u in $(aws iam list-users --query "Users[].UserName" --output text); do
  aws iam list-access-keys --user-name "$u" --query "AccessKeyMetadata[?CreateDate>='2026-09-01'].[UserName, AccessKeyId, CreateDate, Status]" --output text
done

# Roles trusting accounts outside the organization
aws iam list-roles --query "Roles[].[RoleName, AssumeRolePolicyDocument.Statement[].Principal.AWS]" --output json

# Identity providers
aws iam list-saml-providers && aws iam list-open-id-connect-providers

# Lambda functions and the rules that trigger them (per region)
aws lambda list-functions --query "Functions[].[FunctionName, LastModified, Role]" --output text
aws events list-rules --query "Rules[].[Name, ScheduleExpression, State]" --output text
```

## 4. Python: compare trust policies with your organization's accounts

```python
import boto3, json
org_accounts = {a["Id"] for p in boto3.client("organizations").get_paginator("list_accounts").paginate() for a in p["Accounts"]}
iam = boto3.client("iam")
for page in iam.get_paginator("list_roles").paginate():
    for role in page["Roles"]:
        for st in role["AssumeRolePolicyDocument"]["Statement"]:
            principals = st.get("Principal", {}).get("AWS", [])
            for p in [principals] if isinstance(principals, str) else principals:
                acct = p.split(":")[4] if p.startswith("arn:") else p
                if acct == "*" or (acct.isdigit() and acct not in org_accounts):
                    print(role["RoleName"], "trusts", p, json.dumps(st.get("Condition", {})))
```

## Related

- [IAM](identity-access.md)
- [CloudTrail](audit-logging.md)
- [Hypothesis-driven hunting framework](../../tasks/threat-hunting/hypothesis-driven-hunting-framework.md)
- [Azure persistence & hunting](../azure/persistence-hunting.md)

## Sources

- [MITRE ATT&CK IaaS matrix](https://attack.mitre.org/matrices/enterprise/cloud/iaas/)
- [CloudTrail Lake SQL constraints](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-limitations.html)
- [IAM actions, resources and condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsidentityandaccessmanagementiam.html)
