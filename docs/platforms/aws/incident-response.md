---
title: AWS Incident Response & Forensics
platforms: [AWS]
languages: [Bash]
tasks: [Incident Response, Forensics, Investigation]
category: Incident Response
tags: [aws, incident response, containment, quarantine security group, ebs snapshot, revoke sessions, access keys, forensics]
aliases: [isolate ec2 instance, snapshot ebs for forensics, revoke aws role sessions, compromised aws access key, aws ir runbook, aws forensic account]
difficulty: advanced
verified: true
last_verified: 2026-10-12
---

# AWS Incident Response & Forensics

Most AWS incidents start with **leaked credentials**: access keys in code, a stolen SSO session, or instance-role credentials taken through SSRF. Contain the credentials first, then the resources, and preserve evidence in a separate **forensics account** before you rebuild. For the cloud-agnostic process, see [Concept: digital forensics](../../fundamentals/concepts/digital-forensics.md).

!!! warning "Before you run anything"
    Every command was checked against the AWS CLI reference and AWS API definitions (2026-10-12); this guide does not run them against a live tenant. Almost every command here **changes state**. Agree containment with the incident lead before you run it, and record each action with a UTC timestamp.

## 1. Contain the identity

=== "IAM user / access key"

    ```bash
    aws iam list-access-keys --user-name <user>
    aws iam update-access-key --user-name <user> --access-key-id AKIA... --status Inactive   # deactivate, don't delete yet
    aws iam delete-login-profile --user-name <user>                                          # removes console password
    aws iam put-user-policy --user-name <user> --policy-name ir-deny-all \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
    ```

    Keep the key **inactive** rather than deleted until the investigation is done; CloudTrail searches by key ID still work.

=== "Role (stolen temporary credentials)"

    Temporary credentials cannot be revoked one by one. Deny every session issued before now:

    ```bash
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    aws iam put-role-policy --role-name <role> --policy-name AWSRevokeOlderSessions --policy-document "{
      \"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\",
      \"Condition\":{\"DateLessThan\":{\"aws:TokenIssueTime\":\"$now\"}}}]}"
    ```

    This is what the console's **Revoke active sessions** button does. For an **instance role**, also stop the source: enforce IMDSv2 and fix the SSRF ([EC2](compute.md#5-enforce-imdsv2)).

=== "Identity Center user"

    Disable the user in the identity source (Entra ID, Okta or the Identity Center directory), then delete their active sessions in **IAM Identity Center → Users → Active sessions**. Existing role sessions last until expiry, so apply the role revoke above to the permission-set roles they used.

## 2. Isolate an instance

Keep the instance **running** so memory survives. Isolate it with a security group that has no rules, and handle tracked connections.

```bash
vpc=$(aws ec2 describe-instances --instance-ids <id> --query "Reservations[0].Instances[0].VpcId" --output text)
sg=$(aws ec2 create-security-group --group-name ir-quarantine-<case> --description "IR quarantine" --vpc-id "$vpc" --query GroupId --output text)
aws ec2 revoke-security-group-egress --group-id "$sg" --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'
aws ec2 modify-instance-attribute --instance-id <id> --groups "$sg"

aws ec2 modify-instance-attribute --instance-id <id> --disable-api-termination
aws ec2 create-tags --resources <id> --tags Key=ir-case,Value=<case> Key=ir-status,Value=quarantined
aws autoscaling detach-instances --instance-ids <id> --auto-scaling-group-name <asg> --should-decrement-desired-capacity   # if in an ASG
aws ec2 disassociate-iam-instance-profile --association-id <assoc-id>   # find it with describe-iam-instance-profile-associations
```

!!! warning "Tracked connections"
    Changing security groups does not cut connections that are already **tracked** (for example an established SSH session from `0.0.0.0/0`). Apply a deny-all **network ACL** to the subnet as well, or move the ENI to an isolated subnet, to break them.

## 3. Preserve evidence

### EBS snapshots

```bash
for vol in $(aws ec2 describe-instances --instance-ids <id> --query "Reservations[].Instances[].BlockDeviceMappings[].Ebs.VolumeId" --output text); do
  aws ec2 create-snapshot --volume-id "$vol" --description "IR <case> $(date -u +%FT%TZ) from <id>" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=ir-case,Value=<case>}]"
done
```

Share the snapshots with the **forensics account** (re-encrypt with a KMS key that account can use), then create volumes there and attach them **read-only** to an analysis instance in an isolated VPC:

```bash
aws ec2 modify-snapshot-attribute --snapshot-id snap-... --attribute createVolumePermission --operation-type add --user-ids <forensics-account-id>
```

### Memory and volatile data

Collect memory **inside the guest** before stopping (AVML or LiME on Linux, WinPmem on Windows), using SSM Run Command to start the tool and write to an evidence volume or S3 ([Memory acquisition](../../tasks/forensics/memory-acquisition-analysis.md)). Also save instance metadata:

```bash
aws ec2 describe-instances --instance-ids <id> > ir-<case>-instance.json
aws ec2 get-console-output --instance-id <id> --latest --output text > ir-<case>-console.txt
aws ec2 get-console-screenshot --instance-id <id> --query ImageData --output text | base64 -d > ir-<case>-screen.jpg
```

### Logs

Export CloudTrail (all regions), VPC flow logs, GuardDuty findings and relevant S3/ALB logs for the whole window into the forensics account. Lock the evidence bucket with Object Lock.

## 4. Scope the intrusion

```sql
-- CloudTrail Lake: everything the leaked key or role session did, all regions
SELECT eventTime, awsRegion, eventSource, eventName, sourceIPAddress, errorCode, userAgent
FROM <event-data-store-id>
WHERE (userIdentity.accessKeyId = 'AKIA...' OR userIdentity.arn LIKE '%assumed-role/<role>/%')
  AND eventTime > date_add('day', -30, now())
ORDER BY eventTime
```

Typical attacker sequence: `GetCallerIdentity` → enumeration (`List*`, `Describe*`, many `AccessDenied`) → persistence (`CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateAssumeRolePolicy`) → impact (`RunInstances` in unused regions, `GetSecretValue`, S3 `GetObject` bursts, `PutBucketPolicy`). Hunt each step: [Persistence & threat hunting](persistence-hunting.md).

## 5. Contain resources

| Resource | Action |
| :--- | :--- |
| S3 bucket | Re-enable Block Public Access, remove foreign principals from the bucket policy, revoke presigned URLs with a `aws:TokenIssueTime` deny ([S3](storage.md#4-presigned-urls)) |
| Secrets | Rotate every secret the principal could read ([Secrets](keys-secrets.md#2-secrets-manager)) |
| Cryptomining | Find instances in every region (`RunInstances` events), snapshot one for evidence, terminate the rest, and request a billing adjustment from AWS Support |
| EKS | Remove access entries, cordon nodes ([EKS](kubernetes.md#7-incident-actions-change)) |

## 6. Recover

- Rebuild instances from known-good AMIs. Do not clean them in place.
- Delete the keys, users and roles the attacker created only after you have recorded them.
- Open a case with AWS Support (and the AWS CIRT for active incidents) if the account was used for abuse.

## Related

- [Concept: digital forensics](../../fundamentals/concepts/digital-forensics.md)
- [Automated containment runbook](../../tasks/incident-response/automated-containment.md)
- [Azure incident response](../azure/incident-response.md) for the same steps on Azure

## Sources

- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [Revoking IAM role temporary credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)
- [Security group connection tracking](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html)
