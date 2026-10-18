---
title: AWS KMS, Secrets Manager & Parameter Store
platforms: [AWS]
languages: [Bash, Python]
tasks: [Administration, Hardening, Investigation, Incident Response]
category: Secrets
tags: [aws, kms, key policy, secrets manager, parameter store, rotation, encryption, grants]
aliases: [aws kms key policy audit, who read secrets manager secret, rotate secrets manager, ssm parameter store securestring, kms grants list, kms key scheduled deletion]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# AWS KMS, Secrets Manager & Parameter Store

| Service | Holds | Access is decided by |
| :--- | :--- | :--- |
| **AWS KMS** | Encryption keys (never leave KMS unless imported/exported by design) | **Key policy** (mandatory) + IAM policies (only if the key policy allows the account) + **grants** |
| **Secrets Manager** | Secrets with versioning and automatic rotation | IAM + optional **resource policy** + the KMS key that encrypts it |
| **SSM Parameter Store** | Config and `SecureString` values (KMS-encrypted) | IAM + the KMS key |

Reading a secret needs both `secretsmanager:GetSecretValue` (or `ssm:GetParameter`) and `kms:Decrypt` on its key. That second permission is a useful choke point.

!!! warning "Before you run anything"
    Every command was checked against the AWS CLI reference and AWS API definitions (2026-10-12); this guide does not run them against a live tenant. Commands that change state are marked **change**. Never print secret values into terminals that are logged or recorded.

## 1. KMS inventory and key policies

```bash
aws kms list-keys --query "Keys[].KeyId" --output text | tr '\t' '\n' | while read k; do
  aws kms describe-key --key-id "$k" --query "KeyMetadata.{id:KeyId, manager:KeyManager, state:KeyState, usage:KeyUsage, desc:Description}" --output text
done
aws kms list-aliases --output table
aws kms get-key-policy --key-id <key-id> --policy-name default --output text | jq .
aws kms get-key-rotation-status --key-id <key-id>
aws kms list-grants --key-id <key-id> --query "Grants[].{grantee:GranteePrincipal, ops:Operations, retiring:RetiringPrincipal}" --output table
```

Red flags in a key policy: `"Principal": {"AWS": "*"}` without conditions; external account IDs; `kms:PutKeyPolicy` or `kms:CreateGrant` given broadly. Grants are easy to miss and do not show in IAM.

## 2. Secrets Manager

```bash
aws secretsmanager list-secrets --query "SecretList[].{name:Name, rotation:RotationEnabled, lastRotated:LastRotatedDate, lastAccessed:LastAccessedDate, kms:KmsKeyId}" --output table
aws secretsmanager get-resource-policy --secret-id <name>
aws secretsmanager describe-secret --secret-id <name> --query "VersionIdsToStages"

# Value (only when needed)
aws secretsmanager get-secret-value --secret-id <name> --query SecretString --output text
```

Rotate (**change**):

```bash
aws secretsmanager rotate-secret --secret-id <name>                    # uses the configured rotation Lambda
aws secretsmanager put-secret-value --secret-id <name> --secret-string file://new-secret.json   # manual new version
```

`file://` keeps the value out of shell history. After a manual rotation, update or restart every consumer that cached the old value.

## 3. Parameter Store

```bash
aws ssm describe-parameters --query "Parameters[].{name:Name, type:Type, key:KeyId, modified:LastModifiedDate}" --output table
aws ssm get-parameter --name /prod/db/password --with-decryption --query Parameter.Value --output text     # only when needed
aws ssm get-parameter-history --name /prod/db/password --query "Parameters[].{v:Version, by:LastModifiedUser, at:LastModifiedDate}"
```

`String` and `StringList` parameters are stored unencrypted. Search them for secrets that should have been `SecureString`.

## 4. Audit secret access

All of these calls are CloudTrail **management** events, so they are logged by default.

```sql
-- CloudTrail Lake: who read secrets, and from where
SELECT eventTime, userIdentity.arn, sourceIPAddress, element_at(requestParameters, 'secretId') AS secret
FROM <event-data-store-id>
WHERE eventSource = 'secretsmanager.amazonaws.com' AND eventName = 'GetSecretValue'
  AND eventTime > date_add('day', -7, now())
ORDER BY eventTime DESC
```

```sql
-- One principal reading many distinct secrets in an hour (credential harvesting)
SELECT userIdentity.arn, date_trunc('hour', from_iso8601_timestamp(eventTime)) AS hr,
       count(DISTINCT element_at(requestParameters, 'secretId')) AS secrets
FROM <event-data-store-id>
WHERE eventName IN ('GetSecretValue', 'BatchGetSecretValue')
GROUP BY 1, 2 HAVING count(DISTINCT element_at(requestParameters, 'secretId')) > 10
```

KMS `Decrypt` events show which principal decrypted what, including Parameter Store `SecureString` reads (`encryptionContext` names the parameter).

## 5. Deletion protection

- KMS keys cannot be deleted immediately: `ScheduleKeyDeletion` waits 7–30 days. Alert on it; cancel with `aws kms cancel-key-deletion` (**change**). Deleting a key makes everything it encrypted unreadable, which is a ransomware technique ([T1485](https://attack.mitre.org/techniques/T1485/)).
- Secrets Manager deletion has a 7–30 day recovery window: `aws secretsmanager restore-secret --secret-id <name>` (**change**). `--force-delete-without-recovery` skips it; alert on it.

## 6. Python: find plaintext secrets in Parameter Store

```python
import boto3, re
ssm = boto3.client("ssm")
pattern = re.compile(r"(password|secret|token|apikey|api_key)", re.I)
for page in ssm.get_paginator("describe_parameters").paginate(
        ParameterFilters=[{"Key": "Type", "Values": ["String", "StringList"]}]):
    for p in page["Parameters"]:
        if pattern.search(p["Name"]):
            print("plaintext parameter with a secret-like name:", p["Name"])
```

## Related

- [IAM](identity-access.md)
- [Storage](storage.md) (SSE-KMS on buckets)
- [CI/CD secret leak detection](../../detection/sigma/cicd-secret-leak.md)
- [Store service secrets on Linux](../../tasks/administration/linux-service-secrets-storage.md) · [on Windows](../../tasks/administration/windows-service-secrets-storage.md) (reading the secret from a VM with its own identity)

## Sources

- [AWS KMS key policies](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html)
- [Secrets Manager rotation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html)
- [Logging Secrets Manager events with CloudTrail](https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html)
